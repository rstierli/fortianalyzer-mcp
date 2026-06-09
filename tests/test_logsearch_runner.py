"""Regression tests for the shared poll-before-fetch page runner.

These pin the hard contract of ``log_tools._run_logsearch_page`` /
``_run_logsearch_page_unlocked`` discovered against the lab FAZ (7.6.7): the
runner starts a search, polls ``logsearch_count`` (a cheap GET that does NOT
reap the single-use ``tid``) until :func:`log_tools._search_complete`, and then
fetches exactly once. It never loops ``logsearch_start`` on a normally
completing search (the root cause of search-slot exhaustion), bounds all
recovery by a shared ``MAX_SEARCH_REISSUES`` budget and the wall-clock deadline,
caps concurrent in-flight searches, best-effort cancels a leaked tid, and falls
back to a direct fetch only on a proven unsupported ``logsearch_count`` endpoint.
"""

import asyncio

import pytest

import fortianalyzer_mcp.tools.log_tools as log_tools
from fortianalyzer_mcp.tools.log_tools import _run_logsearch_page, _search_complete
from fortianalyzer_mcp.utils.errors import APIError, ResourceNotFoundError

_DEVICE = [{"devid": "All_FortiGate"}]
_WINDOW = {"start": "2024-01-01 00:00:00", "end": "2024-01-01 01:00:00"}


@pytest.fixture(autouse=True)
def _fast_polls(monkeypatch: pytest.MonkeyPatch) -> None:
    """Drop the poll cadence to zero so start->poll->fetch is fast."""
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
    """Records every call; subclasses override count/fetch behavior."""

    def __init__(self) -> None:
        self.ensure_connected_calls = 0
        self.starts: list[int] = []
        self.counts: list[int] = []
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
# Readiness predicate
# =============================================================================


class TestSearchCompletePredicate:
    def test_matched_logs_alone_is_not_complete(self) -> None:
        """matched-logs>0 with progress<100 and scanned<total is NOT complete:
        matches existing proves rows match, not that scanning finished."""
        count = {
            "matched-logs": 42,
            "progress-percent": 60,
            "scanned-logs": 300,
            "total-logs": 1000,
        }
        assert _search_complete(count) is False

    def test_progress_100_is_complete(self) -> None:
        assert _search_complete({"progress-percent": 100}) is True

    def test_scanned_meets_total_is_complete(self) -> None:
        assert _search_complete({"total-logs": 50, "scanned-logs": 50}) is True

    def test_zero_scan_is_not_complete(self) -> None:
        """A just-started 0>=0 scan must not read as complete."""
        assert _search_complete({"total-logs": 0, "scanned-logs": 0}) is False


# =============================================================================
# No-slot-exhaustion: exactly one start / >=1 count / exactly one fetch
# =============================================================================


class _NormalFake(_BaseFake):
    """A normally-completing async search: count climbs, then one valid fetch."""

    def __init__(self, dataset: list[dict[str, object]], *, polls_to_complete: int = 2) -> None:
        super().__init__()
        self.dataset = dataset
        self.polls_to_complete = polls_to_complete
        self._polls: dict[int, int] = {}

    async def logsearch_count(self, adom: str, tid: int) -> dict[str, object]:
        self.counts.append(tid)
        self._polls[tid] = self._polls.get(tid, 0) + 1
        done = self._polls[tid] >= self.polls_to_complete
        total = len(self.dataset)
        return {
            "progress-percent": 100 if done else 30,
            "scanned-logs": total if done else 0,
            "total-logs": total,
        }

    async def logsearch_fetch(self, *, adom: str, tid: int, limit: int, offset: int) -> dict:
        self.fetches.append(tid)
        if self._polls.get(tid, 0) < self.polls_to_complete:
            raise ResourceNotFoundError(f"Invalid tid {tid}: not complete.", code=-1)
        return {
            "percentage": 100,
            "data": self.dataset[offset : offset + limit],
            "total-count": len(self.dataset),
        }


class TestNoSlotExhaustion:
    async def test_one_start_one_fetch_many_counts(self) -> None:
        fake = _NormalFake(_rows(5), polls_to_complete=3)
        page = await _run(fake, limit=10)

        assert page["timed_out"] is False
        assert page["logs"] == _rows(5)
        assert page["total"] == 5
        # The contract: exactly one start, >=1 count, exactly one fetch.
        assert len(fake.starts) == 1
        assert len(fake.counts) >= 1
        assert len(fake.fetches) == 1
        assert fake.cancels == []  # delivered fetch -> no leak cleanup

    async def test_zero_result_clean_success(self) -> None:
        """progress 100 / scanned 0 / total 0 + fetch total-count 0 -> clean
        empty success with one start, one count, one fetch, no reissue."""

        class _ZeroFake(_BaseFake):
            async def logsearch_count(self, adom: str, tid: int) -> dict[str, object]:
                self.counts.append(tid)
                return {"progress-percent": 100, "scanned-logs": 0, "total-logs": 0}

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
        assert len(fake.counts) == 1
        assert len(fake.fetches) == 1


# =============================================================================
# Shared recovery-budget cap
# =============================================================================


class TestSharedBudgetCap:
    async def test_always_invalid_count_caps_starts_then_times_out(self) -> None:
        """A fake that always invalidates count exhausts the shared budget:
        1 + MAX_SEARCH_REISSUES starts, then timed_out."""

        class _AlwaysInvalidCount(_BaseFake):
            async def logsearch_count(self, adom: str, tid: int) -> dict[str, object]:
                self.counts.append(tid)
                raise ResourceNotFoundError(f"Invalid tid {tid} reaped.", code=-1)

            async def logsearch_fetch(
                self, *, adom: str, tid: int, limit: int, offset: int
            ) -> dict:
                raise AssertionError("must not fetch when count never completes")

        fake = _AlwaysInvalidCount()
        page = await _run(fake, limit=10)

        assert page["timed_out"] is True
        assert len(fake.starts) == 1 + log_tools.MAX_SEARCH_REISSUES

    async def test_always_premature_100_caps_starts(self) -> None:
        """A fake that always returns premature-empty-100 hits the same cap."""

        class _AlwaysPremature(_BaseFake):
            async def logsearch_count(self, adom: str, tid: int) -> dict[str, object]:
                self.counts.append(tid)
                return {"progress-percent": 100, "scanned-logs": 9, "total-logs": 9}

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
    async def test_count_completes_after_deadline_does_not_fetch(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The post-count deadline re-check guard: ``logsearch_count`` reports
        COMPLETE promptly (progress 100), but by the time the runner re-checks
        the deadline it has already passed -- so the runner returns timed_out
        WITHOUT fetching and cancels the live tid. We drive the loop clock past
        the deadline once the count returns complete (rather than burning real
        time in the count, which would exit via the count wait_for TimeoutError
        branch instead and leave the post-count guard uncovered)."""

        loop = asyncio.get_event_loop()
        real_time = loop.time
        ticks = {"count_done": False}
        # Start measuring from a fixed base so the bump is deterministic.
        base = real_time()

        def _fake_time() -> float:
            # Once the count has reported complete, jump the clock far past the
            # deadline so the post-count re-check (loop.time() >= deadline) fires.
            if ticks["count_done"]:
                return base + 10_000.0
            return real_time()

        monkeypatch.setattr(loop, "time", _fake_time)

        fetch_calls = {"n": 0}

        class _CompleteThenDeadlinePassed(_BaseFake):
            async def logsearch_count(self, adom: str, tid: int) -> dict[str, object]:
                self.counts.append(tid)
                # Return COMPLETE promptly; only after we hand back a complete
                # count do we advance the clock past the deadline.
                result = {"progress-percent": 100, "scanned-logs": 5, "total-logs": 5}
                ticks["count_done"] = True
                return result

            async def logsearch_fetch(
                self, *, adom: str, tid: int, limit: int, offset: int
            ) -> dict:
                fetch_calls["n"] += 1
                raise AssertionError("must not fetch after the deadline")

        fake = _CompleteThenDeadlinePassed()
        page = await _run(fake, limit=10, timeout=1)

        assert page["timed_out"] is True
        assert fetch_calls["n"] == 0  # post-count guard skipped the fetch
        assert fake.fetches == []
        assert fake.cancels == [fake.starts[0]]  # live tid best-effort cancelled

    async def test_no_new_start_once_deadline_passed_on_reissue(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The loop-top 'no new start past deadline' guard: an invalid-tid count
        forces a reissue, but the deadline has elapsed before the second loop
        iteration begins, so the runner hits ``loop.time() >= deadline`` at the
        top of the loop and returns timed_out WITHOUT issuing a second
        logsearch_start. This proves a reaping appliance cannot spin
        logsearch_start past the budget (the runaway that caused slot
        exhaustion). We advance the loop clock past the deadline as soon as the
        first count signals the reissue."""

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
            async def logsearch_count(self, adom: str, tid: int) -> dict[str, object]:
                self.counts.append(tid)
                # Trip the reissue path, then jump the clock past the deadline so
                # the loop-top guard short-circuits the second start.
                ticks["reissue_signalled"] = True
                raise ResourceNotFoundError(f"Invalid tid {tid} reaped.", code=-1)

            async def logsearch_fetch(
                self, *, adom: str, tid: int, limit: int, offset: int
            ) -> dict:
                raise AssertionError("must not fetch when count never completes")

        fake = _InvalidThenDeadlinePassed()
        page = await _run(fake, limit=10, timeout=1)

        assert page["timed_out"] is True
        # Bounded: exactly one start; the loop-top guard prevented a second.
        assert len(fake.starts) == 1
        assert fake.fetches == []
        # The first (still-live) tid is best-effort cancelled on the way out.
        assert fake.cancels == [fake.starts[0]]

    async def test_incomplete_count_then_deadline_in_poll_sleep_times_out(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The mid-poll-sleep deadline re-check: ``logsearch_count`` reports
        INCOMPLETE, and the deadline elapses before the next poll -- the runner
        re-checks the remaining budget after the (incomplete) count and returns
        timed_out instead of sleeping/polling again. We advance the loop clock
        past the deadline as soon as the count returns incomplete."""

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
            async def logsearch_count(self, adom: str, tid: int) -> dict[str, object]:
                self.counts.append(tid)
                # Not complete: progress < 100 and scanned < total. After we
                # return, the clock jumps past the deadline so the re-check that
                # guards the poll-sleep fires.
                result = {"progress-percent": 20, "scanned-logs": 0, "total-logs": 9}
                ticks["incomplete"] = True
                return result

            async def logsearch_fetch(
                self, *, adom: str, tid: int, limit: int, offset: int
            ) -> dict:
                raise AssertionError("must not fetch a stalled, timed-out search")

        fake = _ForeverIncomplete()
        page = await _run(fake, limit=10, timeout=1)

        assert page["timed_out"] is True
        assert len(fake.counts) == 1  # re-checked after one incomplete count
        assert fake.fetches == []
        assert fake.cancels == [fake.starts[0]]

    async def test_count_overruns_remaining_budget_times_out(self) -> None:
        """The count wait_for TimeoutError branch: ``logsearch_count`` awaits
        longer than the remaining wall-clock budget, so ``asyncio.wait_for``
        cancels the count and the runner returns page timed_out without fetching,
        best-effort cancelling the live tid."""

        class _SlowCount(_BaseFake):
            async def logsearch_count(self, adom: str, tid: int) -> dict[str, object]:
                self.counts.append(tid)
                # Sleep past the remaining budget; wait_for must cancel us.
                await asyncio.sleep(10)
                return {"progress-percent": 100, "scanned-logs": 5, "total-logs": 5}

            async def logsearch_fetch(
                self, *, adom: str, tid: int, limit: int, offset: int
            ) -> dict:
                raise AssertionError("must not fetch after a count timeout")

        fake = _SlowCount()
        page = await _run(fake, limit=10, timeout=1)

        assert page["timed_out"] is True
        assert fake.fetches == []
        assert fake.cancels == [fake.starts[0]]

    async def test_fetch_overruns_remaining_budget_times_out(self) -> None:
        """The fetch wait_for TimeoutError branch: ``logsearch_count`` completes
        immediately, but ``logsearch_fetch`` awaits longer than the remaining
        wall-clock budget, so ``asyncio.wait_for`` cancels the fetch and the
        runner returns page timed_out -- best-effort cancelling the live tid."""

        class _SlowFetch(_BaseFake):
            async def logsearch_count(self, adom: str, tid: int) -> dict[str, object]:
                self.counts.append(tid)
                return {"progress-percent": 100, "scanned-logs": 5, "total-logs": 5}

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
        assert fake.fetches == [fake.starts[0]]  # fetch was attempted, then cancelled
        assert page["logs"] == []
        # Live tid best-effort cancelled on the non-delivered exit.
        assert fake.cancels == [fake.starts[0]]


# =============================================================================
# Leak cleanup: cancel the live tid on non-delivered exits
# =============================================================================


class TestLeakCleanup:
    async def test_generic_count_error_reraises_and_cancels(self) -> None:
        class _GenericCountError(_BaseFake):
            async def logsearch_count(self, adom: str, tid: int) -> dict[str, object]:
                self.counts.append(tid)
                raise RuntimeError("connection reset by peer")

            async def logsearch_fetch(
                self, *, adom: str, tid: int, limit: int, offset: int
            ) -> dict:
                raise AssertionError("must not fetch after a generic count error")

        fake = _GenericCountError()
        with pytest.raises(RuntimeError, match="connection reset"):
            await _run(fake, limit=10)
        assert fake.cancels == [fake.starts[0]]  # leaked tid best-effort cancelled

    async def test_generic_fetch_error_reraises_and_cancels(self) -> None:
        class _GenericFetchError(_BaseFake):
            async def logsearch_count(self, adom: str, tid: int) -> dict[str, object]:
                self.counts.append(tid)
                return {"progress-percent": 100, "scanned-logs": 5, "total-logs": 5}

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
        """A task cancelled mid-count still issues a (shielded, bounded)
        best-effort logsearch_cancel for the live tid."""
        cancelled_evt = asyncio.Event()

        class _BlockingCount(_BaseFake):
            async def logsearch_count(self, adom: str, tid: int) -> dict[str, object]:
                self.counts.append(tid)
                cancelled_evt.set()
                await asyncio.sleep(10)  # block until the caller cancels us
                return {"progress-percent": 100}

            async def logsearch_fetch(
                self, *, adom: str, tid: int, limit: int, offset: int
            ) -> dict:
                raise AssertionError("must not fetch a cancelled search")

        fake = _BlockingCount()
        task = asyncio.ensure_future(_run(fake, limit=10, timeout=60))
        await cancelled_evt.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert fake.cancels == [fake.starts[0]]


# =============================================================================
# Compat: unsupported logsearch_count endpoint -> direct fetch fallback
# =============================================================================


class TestCountUnsupportedFallback:
    async def test_unsupported_count_falls_back_to_direct_fetch_and_caches(self) -> None:
        """An 'unknown URL' count error falls back to a single direct fetch on
        the SAME tid (no preceding cancel) and caches the per-client flag so a
        second search skips the count probe entirely."""

        class _NoCountEndpoint(_BaseFake):
            async def logsearch_count(self, adom: str, tid: int) -> dict[str, object]:
                self.counts.append(tid)
                raise APIError("Unknown URL /logsearch/count/", code=-6)

            async def logsearch_fetch(
                self, *, adom: str, tid: int, limit: int, offset: int
            ) -> dict:
                self.fetches.append(tid)
                return {"percentage": 100, "data": _rows(2), "total-count": 2}

        fake = _NoCountEndpoint()
        page = await _run(fake, limit=10)

        assert page["timed_out"] is False
        assert page["logs"] == _rows(2)
        assert len(fake.counts) == 1  # probed once
        assert fake.fetches == [fake.starts[0]]  # direct fetch on the same tid
        assert fake.cancels == []  # delivered fetch -> no cancel before fallback
        assert getattr(fake, "_logsearch_count_unsupported", False) is True

        # A second search makes no further count attempt (cached).
        page2 = await _run(fake, limit=10)
        assert page2["logs"] == _rows(2)
        assert len(fake.counts) == 1  # unchanged: no new count probe

    async def test_invalid_tid_count_does_not_trigger_fallback(self) -> None:
        """An invalid-tid count error re-issues (it is NOT an unsupported
        endpoint) and must not set the count-unsupported cache flag."""

        class _InvalidThenOk(_NormalFake):
            def __init__(self) -> None:
                super().__init__(_rows(3), polls_to_complete=1)
                self._raised = False

            async def logsearch_count(self, adom: str, tid: int) -> dict[str, object]:
                if not self._raised:
                    self._raised = True
                    self.counts.append(tid)
                    raise ResourceNotFoundError("Invalid tid reaped.", code=-1)
                return await super().logsearch_count(adom, tid)

        fake = _InvalidThenOk()
        page = await _run(fake, limit=10)

        assert page["logs"] == _rows(3)
        assert len(fake.starts) == 2  # re-issued, not a fallback
        assert getattr(fake, "_logsearch_count_unsupported", False) is False


# =============================================================================
# Concurrency cap
# =============================================================================


class TestConcurrencyCap:
    async def test_in_flight_searches_bounded_by_limit(self) -> None:
        """Launching more than LOGSEARCH_CONCURRENCY_LIMIT concurrent page runs,
        each blocking inside logsearch_count on an Event, must SATURATE the
        semaphore exactly to the cap: max in-flight == the limit (not less, which
        would mean serialization or a too-small semaphore) and never > the limit
        (the surplus is held back), while all eventually complete."""
        limit = log_tools.LOGSEARCH_CONCURRENCY_LIMIT
        release = asyncio.Event()
        state = {"in_flight": 0, "max_in_flight": 0}

        class _BlockingFake(_BaseFake):
            async def logsearch_count(self, adom: str, tid: int) -> dict[str, object]:
                state["in_flight"] += 1
                state["max_in_flight"] = max(state["max_in_flight"], state["in_flight"])
                try:
                    await release.wait()
                finally:
                    state["in_flight"] -= 1
                return {"progress-percent": 100, "scanned-logs": 1, "total-logs": 1}

            async def logsearch_fetch(
                self, *, adom: str, tid: int, limit: int, offset: int
            ) -> dict:
                self.fetches.append(tid)
                return {"percentage": 100, "data": _rows(1), "total-count": 1}

        # Launch strictly more than the cap so the surplus must wait on the
        # semaphore while the first wave is blocked in logsearch_count.
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
            async def logsearch_count(self, adom: str, tid: int) -> dict[str, object]:
                self.counts.append(tid)
                return {"progress-percent": 20, "scanned-logs": 0, "total-logs": 9}

            async def logsearch_fetch(
                self, *, adom: str, tid: int, limit: int, offset: int
            ) -> dict:
                raise AssertionError("must not fetch a stalled search")

        fake = _StallFake()
        loop = asyncio.get_event_loop()
        before = loop.time()
        page = await _run(fake, limit=10, timeout=10_000)
        elapsed = loop.time() - before

        assert page["timed_out"] is True
        # Clamped to ~1s, not the requested 10_000s.
        assert elapsed < 5
        assert fake.cancels == [fake.starts[0]]
