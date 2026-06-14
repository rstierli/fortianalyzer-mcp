"""Regression tests for the shared poll-fetch page runner.

These pin the hard contract of ``log_tools._run_logsearch_page`` /
``_run_logsearch_page_unlocked``: the runner starts a search, polls
``logsearch_fetch`` against the official FAZ spec endpoint
(``GET /logview/adom/{adom}/logsearch/{tid}``) until the response's
``percentage`` field reaches 100, then returns the page's data and total-count.
It never loops ``logsearch_start`` on a normally completing search (the root
cause of search-slot exhaustion), bounds all recovery by a shared
``MAX_SEARCH_REISSUES`` budget and the wall-clock deadline, caps concurrent
in-flight searches, and best-effort cancels a leaked tid.
"""

import asyncio

import pytest

import fortianalyzer_mcp.tools.log_tools as log_tools
from fortianalyzer_mcp.tools.log_tools import _run_logsearch_page
from fortianalyzer_mcp.utils.errors import ResourceNotFoundError

_DEVICE = [{"devid": "All_FortiGate"}]
_WINDOW = {"start": "2024-01-01 00:00:00", "end": "2024-01-01 01:00:00"}


@pytest.fixture(autouse=True)
def _fast_polls(monkeypatch: pytest.MonkeyPatch) -> None:
    """Drop the poll cadence to zero so start->poll->complete is fast."""
    monkeypatch.setattr(log_tools, "_INITIAL_POLL_DELAY", 0)
    monkeypatch.setattr(log_tools, "POLL_INTERVAL", 0)


def _rows(n: int) -> list[dict[str, object]]:
    return [{"id": i, "srcip": f"10.0.0.{i}"} for i in range(n)]


async def _run(client: object, *, limit: int = 100, offset: int = 0, timeout: int = 60) -> dict:
    return await _run_logsearch_page(
        client,
        adom="root",
        logtype="traffic",
        device_filter=_DEVICE,
        time_range=_WINDOW,
        filter=None,
        offset=offset,
        limit=limit,
        timeout=timeout,
    )


class _BaseFake:
    """Records every call; subclasses override fetch behavior."""

    def __init__(self) -> None:
        self.ensure_connected_calls = 0
        self.starts: list[int] = []
        self.fetches: list[int] = []
        self.cancels: list[int] = []
        self._next_tid = 700

    async def ensure_connected(self) -> None:
        self.ensure_connected_calls += 1

    async def logsearch_start(self, **_kw: object) -> dict[str, int]:
        self._next_tid += 1
        self.starts.append(self._next_tid)
        return {"tid": self._next_tid}

    async def logsearch_cancel(self, adom: str, tid: int) -> dict[str, object]:
        self.cancels.append(tid)
        return {}


# =============================================================================
# No-slot-exhaustion: exactly one start, >=1 fetch, no re-issue on the happy path
# =============================================================================


class _NormalFake(_BaseFake):
    """A normally-completing async search: fetches return partial data with
    percentage<100 a few times, then a final fetch with percentage=100."""

    def __init__(self, dataset: list[dict[str, object]], *, polls_to_complete: int = 2) -> None:
        super().__init__()
        self.dataset = dataset
        self.polls_to_complete = polls_to_complete
        self._polls: dict[int, int] = {}

    async def logsearch_fetch(self, *, adom: str, tid: int, limit: int, offset: int) -> dict:
        self.fetches.append(tid)
        self._polls[tid] = self._polls.get(tid, 0) + 1
        done = self._polls[tid] >= self.polls_to_complete
        total = len(self.dataset)
        return {
            "percentage": 100 if done else 30,
            "data": self.dataset[offset : offset + limit] if done else [],
            "total-count": total,
        }


class TestNoSlotExhaustion:
    async def test_one_start_many_fetches(self) -> None:
        fake = _NormalFake(_rows(5), polls_to_complete=3)
        page = await _run(fake, limit=10)

        assert page["timed_out"] is False
        assert page["logs"] == _rows(5)
        assert page["total"] == 5
        # The contract: exactly one start; multiple fetches polled until percentage=100.
        assert len(fake.starts) == 1
        assert len(fake.fetches) == 3
        assert fake.cancels == []  # delivered fetch -> no leak cleanup

    async def test_zero_result_clean_success(self) -> None:
        """A search whose first fetch returns percentage=100 with an empty data
        page and total-count=0 is a clean empty success (one start, one fetch)."""

        class _ZeroFake(_BaseFake):
            async def logsearch_fetch(
                self, *, adom: str, tid: int, limit: int, offset: int
            ) -> dict:
                self.fetches.append(tid)
                return {"percentage": 100, "data": [], "total-count": 0}

        fake = _ZeroFake()
        page = await _run(fake, limit=10)

        assert page["timed_out"] is False
        assert page["logs"] == []
        assert page["total"] == 0
        assert len(fake.starts) == 1
        assert len(fake.fetches) == 1


# =============================================================================
# Shared recovery-budget cap
# =============================================================================


class TestSharedBudgetCap:
    async def test_always_invalid_fetch_caps_starts_then_times_out(self) -> None:
        """A fake that always raises invalid-tid from fetch exhausts the shared
        budget: 1 + MAX_SEARCH_REISSUES starts, then timed_out."""

        class _AlwaysInvalidFetch(_BaseFake):
            async def logsearch_fetch(
                self, *, adom: str, tid: int, limit: int, offset: int
            ) -> dict:
                self.fetches.append(tid)
                raise ResourceNotFoundError(f"Invalid tid {tid} reaped.", code=-1)

        fake = _AlwaysInvalidFetch()
        page = await _run(fake, limit=10)

        assert page["timed_out"] is True
        assert len(fake.starts) == 1 + log_tools.MAX_SEARCH_REISSUES

    async def test_always_premature_100_caps_starts(self) -> None:
        """A fake that always returns premature-empty-100 hits the same cap."""

        class _AlwaysPremature(_BaseFake):
            async def logsearch_fetch(
                self, *, adom: str, tid: int, limit: int, offset: int
            ) -> dict:
                self.fetches.append(tid)
                # 100% complete but empty while total claims rows here.
                return {"percentage": 100, "data": [], "total-count": 9}

        fake = _AlwaysPremature()
        page = await _run(fake, limit=10)

        # The last premature page is accepted (not a timeout) once the budget is
        # spent, but the start count is bounded by 1 + MAX_SEARCH_REISSUES.
        assert page["logs"] == []
        assert len(fake.starts) == 1 + log_tools.MAX_SEARCH_REISSUES


# =============================================================================
# Deadline behavior
# =============================================================================


class TestDeadline:
    async def test_no_new_start_once_deadline_passed_on_reissue(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The loop-top 'no new start past deadline' guard: an invalid-tid fetch
        forces a reissue, but the deadline has elapsed before the second loop
        iteration begins, so the runner hits ``loop.time() >= deadline`` at the
        top of the loop and returns timed_out WITHOUT issuing a second
        logsearch_start. This proves a reaping appliance cannot spin
        logsearch_start past the budget (the runaway that caused slot
        exhaustion). We advance the loop clock past the deadline as soon as the
        first fetch signals the reissue."""

        loop = asyncio.get_event_loop()
        real_time = loop.time
        ticks = {"reissue_signalled": False}
        base = real_time()

        def _fake_time() -> float:
            if ticks["reissue_signalled"]:
                return base + 10_000.0
            return real_time()

        monkeypatch.setattr(loop, "time", _fake_time)

        class _InvalidThenDeadlinePassed(_BaseFake):
            async def logsearch_fetch(
                self, *, adom: str, tid: int, limit: int, offset: int
            ) -> dict:
                self.fetches.append(tid)
                # Trip the reissue path, then jump the clock past the deadline so
                # the loop-top guard short-circuits the second start.
                ticks["reissue_signalled"] = True
                raise ResourceNotFoundError(f"Invalid tid {tid} reaped.", code=-1)

        fake = _InvalidThenDeadlinePassed()
        page = await _run(fake, limit=10, timeout=1)

        assert page["timed_out"] is True
        # Bounded: exactly one start; the loop-top guard prevented a second.
        assert len(fake.starts) == 1
        # The first (still-live) tid is best-effort cancelled on the way out.
        assert fake.cancels == [fake.starts[0]]

    async def test_incomplete_then_deadline_in_poll_sleep_times_out(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The mid-poll-sleep deadline re-check: ``logsearch_fetch`` reports
        percentage<100, and the deadline elapses before the next poll -- the
        runner re-checks the remaining budget after the (incomplete) fetch and
        returns timed_out instead of sleeping/polling again. We advance the loop
        clock past the deadline as soon as the fetch returns incomplete."""

        loop = asyncio.get_event_loop()
        real_time = loop.time
        ticks = {"incomplete": False}
        base = real_time()

        def _fake_time() -> float:
            if ticks["incomplete"]:
                return base + 10_000.0
            return real_time()

        monkeypatch.setattr(loop, "time", _fake_time)

        class _ForeverIncomplete(_BaseFake):
            async def logsearch_fetch(
                self, *, adom: str, tid: int, limit: int, offset: int
            ) -> dict:
                self.fetches.append(tid)
                # Not complete: percentage < 100. After we return, the clock
                # jumps past the deadline so the re-check that guards the
                # poll-sleep fires.
                ticks["incomplete"] = True
                return {"percentage": 20, "data": [], "total-count": 9}

        fake = _ForeverIncomplete()
        page = await _run(fake, limit=10, timeout=1)

        assert page["timed_out"] is True
        assert len(fake.fetches) == 1  # re-checked after one incomplete fetch
        assert fake.cancels == [fake.starts[0]]

    async def test_fetch_overruns_remaining_budget_times_out(self) -> None:
        """The fetch wait_for TimeoutError branch: ``logsearch_fetch`` awaits
        longer than the remaining wall-clock budget, so ``asyncio.wait_for``
        cancels the fetch and the runner returns page timed_out -- best-effort
        cancelling the live tid."""

        class _SlowFetch(_BaseFake):
            async def logsearch_fetch(
                self, *, adom: str, tid: int, limit: int, offset: int
            ) -> dict:
                self.fetches.append(tid)
                # Sleep well past the remaining budget; wait_for must cancel us.
                await asyncio.sleep(10)
                return {"percentage": 100, "data": _rows(1), "total-count": 1}

        fake = _SlowFetch()
        page = await _run(fake, limit=10, timeout=1)

        assert page["timed_out"] is True
        # Live tid best-effort cancelled on the non-delivered exit.
        assert fake.cancels == [fake.starts[0]]


# =============================================================================
# Leak cleanup: cancel the live tid on non-delivered exits
# =============================================================================


class TestLeakCleanup:
    async def test_generic_fetch_error_reraises_and_cancels(self) -> None:
        class _GenericFetchError(_BaseFake):
            async def logsearch_fetch(
                self, *, adom: str, tid: int, limit: int, offset: int
            ) -> dict:
                self.fetches.append(tid)
                raise RuntimeError("disk full")

        fake = _GenericFetchError()
        with pytest.raises(RuntimeError, match="disk full"):
            await _run(fake, limit=10)
        assert fake.cancels == [fake.starts[0]]

    async def test_cancelled_task_best_effort_cancels_tid(self) -> None:
        """A task cancelled mid-fetch still issues a (shielded, bounded)
        best-effort logsearch_cancel for the live tid."""
        cancelled_evt = asyncio.Event()

        class _BlockingFetch(_BaseFake):
            async def logsearch_fetch(
                self, *, adom: str, tid: int, limit: int, offset: int
            ) -> dict:
                self.fetches.append(tid)
                cancelled_evt.set()
                await asyncio.sleep(10)  # block until the caller cancels us
                return {"percentage": 100, "data": [], "total-count": 0}

        fake = _BlockingFetch()
        task = asyncio.ensure_future(_run(fake, limit=10, timeout=60))
        await cancelled_evt.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert fake.cancels == [fake.starts[0]]


# =============================================================================
# Concurrency cap
# =============================================================================


class TestConcurrencyCap:
    async def test_in_flight_searches_bounded_by_limit(self) -> None:
        """Launching more than LOGSEARCH_CONCURRENCY_LIMIT concurrent page runs,
        each blocking inside logsearch_fetch on an Event, must SATURATE the
        semaphore exactly to the cap: max in-flight == the limit (not less, which
        would mean serialization or a too-small semaphore) and never > the limit
        (the surplus is held back), while all eventually complete."""
        limit = log_tools.LOGSEARCH_CONCURRENCY_LIMIT
        release = asyncio.Event()
        state = {"in_flight": 0, "max_in_flight": 0}

        class _BlockingFake(_BaseFake):
            async def logsearch_fetch(
                self, *, adom: str, tid: int, limit: int, offset: int
            ) -> dict:
                self.fetches.append(tid)
                state["in_flight"] += 1
                state["max_in_flight"] = max(state["max_in_flight"], state["in_flight"])
                try:
                    await release.wait()
                finally:
                    state["in_flight"] -= 1
                return {"percentage": 100, "data": _rows(1), "total-count": 1}

        # Launch strictly more than the cap so the surplus must wait on the
        # semaphore while the first wave is blocked in logsearch_fetch.
        fakes = [_BlockingFake() for _ in range(limit + 3)]
        tasks = [asyncio.ensure_future(_run(f, limit=5, timeout=60)) for f in fakes]

        # Let the first wave saturate the semaphore, then release everyone.
        for _ in range(50):
            await asyncio.sleep(0)
            if state["in_flight"] >= limit:
                break
        # The cap must be SATURATED, not merely respected: exactly `limit`
        # searches are concurrently blocked, and the surplus is held back.
        assert state["in_flight"] == limit
        assert state["max_in_flight"] == limit
        release.set()

        results = await asyncio.gather(*tasks)
        assert all(r["timed_out"] is False for r in results)
        assert all(r["logs"] == _rows(1) for r in results)
        # Across the whole run the cap was hit exactly, never exceeded.
        assert state["max_in_flight"] == limit


# =============================================================================
# Timeout clamp
# =============================================================================


class TestTimeoutClamp:
    async def test_timeout_above_cap_is_clamped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A timeout far above MAX_SEARCH_TIMEOUT is clamped at the page runner:
        with a tiny cap, a stalled scan times out within the cap even though a
        huge timeout was requested (it cannot monopolize a slot indefinitely)."""
        monkeypatch.setattr(log_tools, "MAX_SEARCH_TIMEOUT", 1)
        monkeypatch.setattr(log_tools, "POLL_INTERVAL", 0.005)
        monkeypatch.setattr(log_tools, "_INITIAL_POLL_DELAY", 0.005)

        class _StallFake(_BaseFake):
            async def logsearch_fetch(
                self, *, adom: str, tid: int, limit: int, offset: int
            ) -> dict:
                self.fetches.append(tid)
                return {"percentage": 20, "data": [], "total-count": 9}

        fake = _StallFake()
        loop = asyncio.get_event_loop()
        before = loop.time()
        page = await _run(fake, limit=10, timeout=10_000)
        elapsed = loop.time() - before

        assert page["timed_out"] is True
        # Clamped to ~1s, not the requested 10_000s.
        assert elapsed < 5
        assert fake.cancels == [fake.starts[0]]
