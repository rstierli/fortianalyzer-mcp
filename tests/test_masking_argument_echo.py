"""A token sent as a tool argument must not come back as its plaintext.

With masking on, the wrapper resolves a token in the arguments of a read-only
tool before the tool body runs, and a tool echoes what it was called with.
Three things keep the plaintext from leaving again:

- an argument that names a thing is never resolved (``NAMING_ARGS`` beside
  ``FIELD_NAME_ARGS`` in ``masking/fields.py``);
- what was resolved is recorded for the call, each value whole and each token
  inside it, and the output side puts the caller's own text back under every
  key it scans, ahead of the device-identity keep set;
- a refusal does not hand back a piece of what it refused: a refused skill
  call is reported without its input, and a message cut to its length bound
  loses what the cut left of a recorded value.

The first is a deny-list and the second depends on the key that carries the
echo, so both fail open for the next new argument. This sweep is the other
half. It wraps every tool the server registers the way a masked deployment
wraps it, calls every read-only tool and every skill with a token in each
parameter in turn, in each shape of ``SHAPES``, and asserts that the plaintext
is nowhere in the reply, keys included.

No appliance: the client is a fake that answers every call with an empty
success. The sweep therefore cannot see an echo that only a found record or a
written file produces, nor one that depends on the value of a second
parameter. It looks for the plaintext whole, as it stands or with a backslash
before some of its characters, which is how a substring filter writes it. A
reply that holds only a cut of it passes.
"""

from __future__ import annotations

import asyncio
import inspect
import os
import re
import types
import typing
import urllib.parse
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel

import fortianalyzer_mcp.server as server_module
import fortianalyzer_mcp.utils.config as config_module
from fortianalyzer_mcp.masking.fpe_engine import FPEEngine
from fortianalyzer_mcp.masking.wrapper import OutputMasker, install_masking
from fortianalyzer_mcp.query.filters import FilterCondition
from fortianalyzer_mcp.skills.catalog import SKILLS
from fortianalyzer_mcp.tool_annotations import READ_ONLY
from tests.conftest import import_dispatcher_isolated

# Throwaway test key, the same value tests/test_masking_wrapper.py uses.
KEY = "2DE79D232DF5585D68CE47882AE256D6"

CUSTOM_RANGE = "2024-01-01 00:00:00|2024-01-02 00:00:00"

#: The plaintexts and the type each is minted as, because validators split
#: the routes: a name validator (ADOM, device, vdom) refuses the dotted name
#: and the addresses and accepts the plain name, and an address validator
#: accepts only an address. Between them a parameter is swept on its refusal
#: and past it. One holds an underscore, which a substring filter does not
#: write as it stands. Two are shorter than the four characters pass 2 asks of
#: a value a row carried before it looks for it in prose: a value the caller's
#: token resolved to is looked for whatever its length. They are letters no
#: word, key or token of a reply holds in that order, because the sweep looks
#: for a plaintext as a substring.
PLAINTEXTS = {
    "fw-core.example.net": "hostname",
    "fw-core-01": "hostname",
    "192.0.2.77": "ip",
    "2001:db8::77": "ip",
    "jdoe-probe": "username",
    "svc_bak_probe": "username",
    "qzx": "username",
    "qj": "username",
}

#: Every operator of a structured filter condition. Each is compiled into the
#: filter its own way, and a tool echoes the filter it built.
FILTER_OPS = typing.get_args(FilterCondition.model_fields["op"].annotation)

#: How the token sits in the argument: alone, inside a phrase, and inside a
#: bracketed value, which is the shape a validator takes apart before it
#: quotes one part.
SHAPES = {
    "whole": "{}",
    "phrase": "probe {}",
    "bracketed": "probe[{}]",
}

#: Annotations a string cannot arrive in. The protocol layer types a tool's
#: arguments before the wrapper sees them, so a tool parameter that is only
#: ever one of these never holds a token and is not swept. Any other parameter
#: must be: ``_slots`` has to know how to put a string in it, or the sweep
#: fails for having skipped it.
NOT_TEXT = (int, float, bool, type(None))

#: A valid value for the parameters whose validator would otherwise stop
#: every call to the tool before it reads anything else.
BENIGN: dict[str, Any] = {
    "logtype": "traffic",
    "time_range": CUSTOM_RANGE,
    "view_name": "top-sources",
    "skill": "log_search",
    "indicator_type": "IP",
}

#: A subject for the tools and skills that refuse to run without one although
#: no single parameter is required, by tool name or skill id. A parameter that
#: only matters beside a subject is swept there too.
SUBJECT: dict[str, dict[str, Any]] = {
    "analyze_policy_traffic": {"policy_ids": [1]},
    "get_linked_indicators": {"alert_id": "202401010000000001"},
    "asset_lookup": {"epids": [1]},
    "hunt": {"ttp": "T1059"},
    "identity_lookup": {"euids": [1]},
    "identity_profile": {"euid": 1},
    "investigate": {"alert_id": "202401010000000001"},
    "investigate_deep": {"entity": "epid:1"},
    "reports": {"action": "fetch", "tid": "00000000-0000-0000-0000-000000000001"},
    "risk_assessment": {"epid": 1},
    "threat_intel": {"alert_id": "202401010000000001"},
    "triage": {"alert_id": "202401010000000001"},
}

skip_if_dynamic_mode = pytest.mark.skipif(
    os.environ.get("FAZ_TOOL_MODE") == "dynamic",
    reason="the sweep reads the full-mode tool set off the shared server",
)


class _AnyName(str):
    """A device name that matches whatever name the caller asked for."""

    def __eq__(self, other: object) -> bool:
        return True

    __hash__ = str.__hash__


class PermissiveClient:
    """Answers every appliance call with an empty success, and keeps the calls.

    One exception: ``get_logstats`` lists a device under whatever name was
    asked for while ``known_device`` is set, so a tool that looks a device up
    first gets past the lookup and reaches the echoes on its success route.
    """

    def __init__(self) -> None:
        self.known_device = True
        self.seen: list[str] = []

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__"):
            raise AttributeError(name)

        async def call(*args: Any, **kwargs: Any) -> Any:
            if name == "get_system_timezone":
                return None
            self.seen.append(repr((name, args, kwargs)))
            if name == "get_logstats" and self.known_device:
                device = {"devname": _AnyName("any"), "devid": "FGT60F0000000001"}
                return {"data": {"devs": [device]}}
            return {
                "data": [],
                "status": {"code": 0, "message": "OK"},
                "tid": 4242,
                "percentage": 100,
                "total-count": 0,
            }

        return call


def _benign(name: str, annotation: Any) -> Any:
    """A harmless value of the parameter's type."""
    if name in BENIGN:
        return BENIGN[name]
    origin, args = typing.get_origin(annotation), typing.get_args(annotation)
    if origin is typing.Literal:
        return args[0]
    if origin in (typing.Union, types.UnionType):
        return _benign(name, args[0])
    if annotation is bool:
        return False
    if annotation is int:
        return 1
    if origin is list:
        return ["probe1"] if args and args[0] is str else []
    return "probe1"


def _required(model: type[BaseModel]) -> dict[str, Any]:
    return {
        name: _benign(name, field.annotation)
        for name, field in model.model_fields.items()
        if field.is_required()
    }


def _takes_text(annotation: Any) -> bool:
    """Whether a string can arrive in a tool parameter of this type."""
    origin, args = typing.get_origin(annotation), typing.get_args(annotation)
    if origin in (typing.Union, types.UnionType):
        return any(_takes_text(arg) for arg in args)
    if origin is list and args:
        return _takes_text(args[0])
    return annotation not in NOT_TEXT


def _slots(annotation: Any, text: str) -> Iterator[Any]:
    """Every value of this type that carries ``text`` in one string.

    A ``Literal`` takes any string on the wire and answers with a refusal, and
    a refusal is a reply too. ``Any`` is also what an unannotated parameter is
    swept as. A type this does not know yields nothing, and the sweep then
    fails for the parameter it could not fill.
    """
    origin, args = typing.get_origin(annotation), typing.get_args(annotation)
    if annotation is str or annotation is Any or origin is typing.Literal:
        yield text
    elif origin in (typing.Union, types.UnionType):
        for arg in args:
            yield from _slots(arg, text)
    elif origin is list or annotation is list:
        for inner in _slots(args[0] if args else Any, text):
            yield [inner]
    elif origin is dict or annotation is dict:
        yield {"probe": text}
    elif annotation is FilterCondition:
        # Tools take conditions as models; the protocol layer builds them.
        for op in FILTER_OPS:
            value = [text] if op in ("in", "not_in") else text
            yield FilterCondition(field="srcname", op=op, value=value)
    elif isinstance(annotation, type) and issubclass(annotation, BaseModel):
        for name, field in annotation.model_fields.items():
            for inner in _slots(field.annotation, text):
                yield {**_required(annotation), name: inner}


def _wire_slots(annotation: Any, text: str) -> Iterator[Any]:
    """``_slots`` for a field of a skill's params.

    The params are one untyped dict on the wire, and the wrapper resolves it
    before the skill's model types anything. Every field therefore takes a
    string, whatever it is declared as: a number, a flag, a list of numbers.
    """
    typed = list(_slots(annotation, text))
    yield from typed
    if text not in typed:
        yield text


def _strings(node: Any, path: str = "$") -> Iterator[tuple[str, str]]:
    """Yield ``(path, text)`` for every string leaf and every string key."""
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str):
                yield f"{path}.<key>", key
            yield from _strings(value, f"{path}.{key}")
    elif isinstance(node, list | tuple):
        for index, item in enumerate(node):
            yield from _strings(item, f"{path}[{index}]")
    elif isinstance(node, str):
        yield path, node


def _paths_holding(reply: Any, plaintext: str) -> list[str]:
    """Where ``plaintext`` sits in ``reply``, as key paths without indexes.

    As a substring of any string leaf and of any dict key, whatever case, and
    also where the reply spells it another way and it is as readable: with a
    backslash before some of its characters, which is how a substring filter
    writes ``_`` and ``%``, or with its percent escapes decoded.
    """
    needles = {plaintext.lower(), urllib.parse.unquote(plaintext).lower()}
    return sorted(
        {
            re.sub(r"\[\d+\]", "[]", path)
            for path, text in _strings(reply)
            for needle in needles
            if needle in text.lower() or needle in text.lower().replace("\\", "")
        }
    )


class Sweep:
    """Calls wrapped tools with a token per parameter and records the echoes."""

    def __init__(self, tools: dict[str, Any], client: PermissiveClient, output_dir: Path) -> None:
        self.tools = tools
        self.client = client
        self.output_dir = output_dir
        engine = FPEEngine(KEY)
        #: plaintext -> its token, minted the way the server mints one
        self.tokens = {plain: engine.mint(vtype, plain) for plain, vtype in PLAINTEXTS.items()}
        self.calls = 0
        #: parameter -> the shapes a token was sent in
        self.sent: dict[str, set[str]] = {}
        self.leaks: list[str] = []
        self.unsettled: list[str] = []
        #: the error codes the replies carried, to show which routes were reached
        self.errors: set[str] = set()

    def _text(self, parameter: str, shape: str, token: str) -> str:
        text = SHAPES[shape].format(token)
        if parameter == "output_dir" and shape != "whole":
            # below a directory the server is allowed to write to
            return str(self.output_dir / text)
        return text

    async def _call(
        self, label: str, shape: str, fn: Any, kwargs: dict[str, Any], plaintext: str
    ) -> None:
        self.calls += 1
        self.sent.setdefault(label, set()).add(shape)
        try:
            reply = fn(**kwargs)
            if inspect.isawaitable(reply):
                reply = await asyncio.wait_for(reply, timeout=10)
        except Exception as exc:  # a tool answers; it does not raise
            self.unsettled.append(f"{label}: {type(exc).__name__}")
            return
        if isinstance(reply, dict) and isinstance(reply.get("error"), str):
            self.errors.add(reply["error"])
        for path in _paths_holding(reply, plaintext):
            entry = f"{label} -> {path}"
            if entry not in self.leaks:
                self.leaks.append(entry)

    def _arguments(
        self, owner: str, base: dict[str, Any], name: str, annotation: Any, slots: Any
    ) -> Iterator[tuple[dict[str, Any], str, str]]:
        """Each set of arguments that puts a token in ``name``.

        With the plaintext and the shape. Alone, and beside the owner's
        subject where it has one.
        """
        subject = SUBJECT.get(owner, {})
        for plaintext, token in self.tokens.items():
            for shape in SHAPES:
                for slot in slots(annotation, self._text(name, shape, token)):
                    alone = {**base, name: slot}
                    beside = {**base, **subject, name: slot}
                    yield alone, plaintext, shape
                    if beside != alone:
                        yield beside, plaintext, shape

    async def tool(self, name: str) -> None:
        """Sweep every parameter of one tool that a string can arrive in."""
        fn = self.tools[name]
        parameters = inspect.signature(fn).parameters
        hints = typing.get_type_hints(inspect.unwrap(fn))
        base = {
            pname: _benign(pname, hints.get(pname))
            for pname, parameter in parameters.items()
            if parameter.default is inspect.Parameter.empty
        }
        if "output_dir" in parameters:
            base["output_dir"] = str(self.output_dir)
        for pname in parameters:
            for kwargs, plaintext, shape in self._arguments(
                name, base, pname, hints.get(pname, Any), _slots
            ):
                await self._call(f"{name}({pname})", shape, fn, kwargs, plaintext)

    async def skills(self) -> None:
        """Sweep every field of every skill's params model, and an unknown key."""
        faz_skill = self.tools["faz_skill"]
        for skill, spec in sorted(SKILLS.items()):
            model = spec.params_model
            fields = {name: field.annotation for name, field in model.model_fields.items()}
            for fname, annotation in {**fields, "unknown_key": str}.items():
                label = "<unknown key>" if fname == "unknown_key" else fname
                for params, plaintext, shape in self._arguments(
                    skill, _required(model), fname, annotation, _wire_slots
                ):
                    await self._call(
                        f"faz_skill[{skill}].{label}",
                        shape,
                        faz_skill,
                        {"skill": skill, "params": params},
                        plaintext,
                    )

    def never_sent(self, *only: str) -> dict[str, list[str]]:
        """The parameters a token did not reach in every shape, and the shapes.

        Read off the tools and the skill catalogue, not off what the sweep
        did, so a tool or a field the sweep skipped is missing here by name.
        ``only`` narrows the question to those tools.
        """
        expected = set()
        for name in only or self.tools:
            fn = self.tools[name]
            hints = typing.get_type_hints(inspect.unwrap(fn))
            expected |= {
                f"{name}({pname})"
                for pname in inspect.signature(fn).parameters
                if _takes_text(hints.get(pname, Any))
            }
        for skill, spec in () if only else SKILLS.items():
            expected |= {f"faz_skill[{skill}].{fname}" for fname in spec.params_model.model_fields}
            expected.add(f"faz_skill[{skill}].<unknown key>")
        return {
            label: sorted(set(SHAPES) - self.sent.get(label, set()))
            for label in sorted(expected)
            if set(SHAPES) - self.sent.get(label, set())
        }


def _masked_server(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, mask_device_identity: bool
) -> tuple[MCPServer, Sweep]:
    """Every registered tool on a private server, wrapped by ``install_masking``.

    The shared server is imported once per process, with or without masking,
    so the wrapper is installed on a private one and each real tool function
    is registered there under its own annotations: the wrapper restores
    arguments for a read-only tool only. A function the shared server has
    already wrapped runs bare inside this boundary, as a tool called from
    another tool does.
    """
    monkeypatch.setenv("FAZ_MASKING_KEY", KEY)
    monkeypatch.setenv("FAZ_ALLOWED_OUTPUT_DIRS", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    # The device-identity setting is the one under test, whatever the session
    # was started with.
    settings = config_module.get_settings().model_copy(
        update={"FAZ_MASK_DEVICE_IDENTITY": mask_device_identity}
    )
    monkeypatch.setattr(config_module, "get_settings", lambda: settings)

    mcp = MCPServer("argument-echo-guard")
    install_masking(mcp)
    for tool in server_module.mcp._tool_manager.list_tools():
        # faz_skill is on the shared server only when skills are enabled there.
        if tool.name != "faz_skill":
            mcp.tool(annotations=tool.annotations)(tool.fn)
    (faz_skill,) = import_dispatcher_isolated("faz_skill")
    mcp.tool(annotations=READ_ONLY)(faz_skill)
    # The discovery tools exist in dynamic mode only.
    server_module.register_dynamic_tools(mcp)

    client = PermissiveClient()
    monkeypatch.setattr(server_module, "faz_client", client)

    real_sleep = asyncio.sleep

    async def no_wait(delay: float = 0, *args: Any, **kwargs: Any) -> None:
        await real_sleep(0)

    # The run-and-wait tools poll; nothing here needs the pause.
    monkeypatch.setattr(asyncio, "sleep", no_wait)

    tools = {
        tool.name: tool.fn
        for tool in mcp._tool_manager.list_tools()
        if getattr(tool.annotations, "read_only_hint", False)
    }
    return mcp, Sweep(tools, client, tmp_path)


@pytest.fixture
def masked(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[MCPServer, Sweep]:
    """The masked server as shipped: device identity is left readable."""
    return _masked_server(monkeypatch, tmp_path, mask_device_identity=False)


@pytest.fixture
def masked_with_device_identity(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[MCPServer, Sweep]:
    """The masked server with ``FAZ_MASK_DEVICE_IDENTITY`` on."""
    return _masked_server(monkeypatch, tmp_path, mask_device_identity=True)


def _register(mcp: MCPServer, sweep: Sweep, fn: Any) -> str:
    """Add a throwaway read-only tool to the masked server and to the sweep."""
    sweep.tools[fn.__name__] = mcp.tool(annotations=READ_ONLY)(fn)
    return str(fn.__name__)


@skip_if_dynamic_mode
class TestNoArgumentEchoesAResolvedToken:
    async def test_no_read_only_tool_or_skill_returns_the_plaintext_of_a_token(
        self, masked: tuple[MCPServer, Sweep]
    ) -> None:
        _, sweep = masked

        for name in sorted(sweep.tools):
            await sweep.tool(name)
        await sweep.skills()
        # Again where a device that was asked for by name is not found.
        assert "device_not_found" not in sweep.errors
        sweep.client.known_device = False
        for name in sorted(sweep.tools):
            if "device" in inspect.signature(sweep.tools[name]).parameters:
                await sweep.tool(name)
        assert "device_not_found" in sweep.errors

        # Every read-only tool the server registers was swept, with the skill
        # dispatcher beside them, and a token reached every parameter a
        # string can arrive in, in every shape.
        registered = {
            tool.name
            for tool in server_module.mcp._tool_manager.list_tools()
            if getattr(tool.annotations, "read_only_hint", False)
        }
        assert registered | {"faz_skill"} <= set(sweep.tools)
        assert sweep.never_sent() == {}, (
            "a parameter was not sent a token in every shape. Teach _slots its "
            "type, or list the type in NOT_TEXT if no string can arrive in it."
        )
        assert sweep.unsettled == [], "a call raised or timed out, so it has no verdict"
        assert sweep.leaks == [], (
            "a reply holds the plaintext of a token the caller sent. If the "
            "parameter names a thing, add it to NAMING_ARGS in masking/fields.py; "
            "if it holds a value, type the key that echoes it."
        )


@skip_if_dynamic_mode
class TestAnEchoOfOnePartOfAValue:
    """Two echoes the sweep's three shapes do not pin by themselves."""

    @pytest.mark.parametrize(
        "shape", ["x[{}", "{}[x", "x[{}]", "x[zq.{}", "x[zq-{}]", "{}.zq[x", "  x[zq.{}  "]
    )
    async def test_a_device_argument_taken_apart_at_a_bracket_holds_no_plaintext(
        self, masked: tuple[MCPServer, Sweep], shape: str
    ) -> None:
        """The device-name check splits ``name[vdom]``. It used to quote the
        half it refused, and that half came back as the plaintext of the
        token that stood there."""
        _, sweep = masked

        for tool, parameter in (
            ("get_device", "name"),
            ("get_device_info", "device"),
            ("list_device_vdoms", "device"),
        ):
            for plaintext, token in sweep.tokens.items():
                reply = await sweep.tools[tool](**{parameter: shape.format(token)})

                assert _paths_holding(reply, plaintext) == [], (tool, plaintext)

    async def test_a_refused_skill_call_holds_no_piece_of_the_plaintext(
        self, masked: tuple[MCPServer, Sweep]
    ) -> None:
        """A refusal used to quote its input cut to a head and a tail, so
        the reply held pieces of the value, which pieces depending on what
        stood around the token. It quotes no input now."""
        _, sweep = masked
        faz_skill = sweep.tools["faz_skill"]

        for plaintext, token in sweep.tokens.items():
            pieces = {plaintext[start : start + 5].lower() for start in range(len(plaintext) - 4)}
            for pad in range(40):
                for value in ("p" * pad + ":" + token, token + ":" + "q" * pad):
                    for params in (
                        {"entity": value, "ttp": "T1059"},
                        {"ttp": "T1059", "note": value},
                        {"ttp": "T1059", "sweep_limit": value},
                    ):
                        reply = await faz_skill(skill="hunt", params=params)

                        assert reply["error"] == "invalid_skill_params"
                        # The caller's own token may come back; the pieces may not.
                        text = str(reply).lower().replace(token.lower(), "")
                        assert [piece for piece in pieces if piece in text] == []

    async def test_a_message_cut_at_its_length_bound_holds_no_piece_of_the_plaintext(
        self, masked: tuple[MCPServer, Sweep]
    ) -> None:
        """A refusal that quotes the whole argument is as long as the
        argument, and an error message is cut at 500 characters. Where the
        cut fell inside the value the token resolved to, the reply held the
        head of it."""
        _, sweep = masked
        search_log_file = sweep.tools["search_log_file"]

        for plaintext, token in sweep.tokens.items():
            pieces = {plaintext[start : start + 4].lower() for start in range(len(plaintext) - 3)}
            for pad in range(400, 500):
                reply = await search_log_file(device="p" * pad + " " + token)

                assert reply["status"] == "error"
                text = str(reply).lower().replace(token.lower(), "")
                assert [piece for piece in pieces if piece in text] == [], pad


def _token_under(key: str, value: str) -> str:
    """The token a caller holds for ``value``: what a row shows under ``key``."""
    token = OutputMasker(FPEEngine(KEY), mask_device_identity=True).mask_result({key: value})[key]
    assert isinstance(token, str) and value not in token
    return token


#: Values a ``like`` clause does not hold as they stand, with a log field
#: that carries each: ``like`` reads ``_`` and ``%`` as wildcards.
RESPELLED = {
    "svc_bak_probe": "user",
    "fw_core_01": "srcname",
    "my_dom.example.net": "hostname",
    "https://www.example.net/a_b/c%20d?x=1": "url",
}


@skip_if_dynamic_mode
class TestAValueWrittenForASubstringMatch:
    """A substring condition is compiled to ``like``, whose writer puts a
    backslash before each ``_`` and ``%`` of the value, and the tool echoes
    the filter it built. The output side looked for the value as the token
    had resolved to it, did not find the respelled one, and the reply held
    the plaintext beside the token."""

    @pytest.mark.parametrize("flag", ["masked", "masked_with_device_identity"])
    @pytest.mark.parametrize("tool", ["query_logs", "search_log_file"])
    @pytest.mark.parametrize("op", ["contains", "not_contains"])
    @pytest.mark.parametrize("plaintext", sorted(RESPELLED))
    async def test_the_echoed_filter_holds_the_token_not_the_value(
        self, flag: str, tool: str, op: str, plaintext: str, request: pytest.FixtureRequest
    ) -> None:
        _, sweep = request.getfixturevalue(flag)
        field = RESPELLED[plaintext]
        token = _token_under(field, plaintext)
        subject = {"device": "probe1"} if tool == "search_log_file" else {}

        reply = await sweep.tools[tool](
            **subject, filters=[FilterCondition(field=field, op=op, value=token)]
        )

        # The appliance was asked for the value, so the search is the one
        # the caller meant, and the caller reads its own token back.
        assert reply["status"] == "success", reply
        sent = " ".join(sweep.client.seen).replace("\\", "")
        assert plaintext in sent
        assert token not in sent
        assert token in reply["filter"]
        assert _paths_holding(reply, plaintext) == []

    @pytest.mark.parametrize("flag", ["masked", "masked_with_device_identity"])
    @pytest.mark.parametrize("op", FILTER_OPS)
    @pytest.mark.parametrize("plaintext", sorted(RESPELLED))
    async def test_no_operator_returns_the_value(
        self, flag: str, op: str, plaintext: str, request: pytest.FixtureRequest
    ) -> None:
        _, sweep = request.getfixturevalue(flag)
        field = RESPELLED[plaintext]
        token = _token_under(field, plaintext)
        value: Any = [token] if op in ("in", "not_in") else token

        for tool, subject in (("query_logs", {}), ("search_log_file", {"device": "probe1"})):
            reply = await sweep.tools[tool](
                **subject, filters=[FilterCondition(field=field, op=op, value=value)]
            )

            assert _paths_holding(reply, plaintext) == [], (tool, reply)

    @pytest.mark.parametrize("flag", ["masked", "masked_with_device_identity"])
    @pytest.mark.parametrize("plaintext", sorted(RESPELLED))
    async def test_a_raw_substring_clause_returns_the_token(
        self, flag: str, plaintext: str, request: pytest.FixtureRequest
    ) -> None:
        """The caller's own ``like`` clause is rewritten around the resolved
        value the same way before the tool sees it."""
        _, sweep = request.getfixturevalue(flag)
        field = RESPELLED[plaintext]
        token = _token_under(field, plaintext)

        for clause in (f'{field} like "%{token}%"', f'{field} like "%x {token} y%"'):
            for tool, subject in (("query_logs", {}), ("search_log_file", {"device": "probe1"})):
                reply = await sweep.tools[tool](**subject, filter=clause)

                assert _paths_holding(reply, plaintext) == [], (tool, reply)

    @pytest.mark.parametrize("flag", ["masked", "masked_with_device_identity"])
    @pytest.mark.parametrize("plaintext", sorted(RESPELLED))
    async def test_the_pivot_a_hunt_reports_holds_the_token_not_the_value(
        self, flag: str, plaintext: str, request: pytest.FixtureRequest
    ) -> None:
        """A hash indicator is searched for as a substring, and the hunt
        reports the clause it searched with."""
        _, sweep = request.getfixturevalue(flag)
        token = _token_under(RESPELLED[plaintext], plaintext)

        reply = await sweep.tools["faz_skill"](
            skill="hunt", params={"indicator": {"type": "Hash", "value": token}}
        )

        assert token in reply["result"]["sweep"]["pivot_filter"], reply
        assert _paths_holding(reply, plaintext) == []

    @pytest.mark.parametrize("flag", ["masked", "masked_with_device_identity"])
    @pytest.mark.parametrize("kind", ["URL", "Hash"])
    async def test_a_url_with_a_percent_escape_comes_back_whole_as_its_token(
        self, flag: str, kind: str, request: pytest.FixtureRequest
    ) -> None:
        """Prose is read percent-decoded first. The URL the token had
        resolved to was not found there as it was recorded, its host was
        found alone, and the path and query stayed readable behind the
        host's token."""
        _, sweep = request.getfixturevalue(flag)
        token = _token_under("url", "https://www.example.net/a_b/c%20d?x=1")

        reply = await sweep.tools["faz_skill"](
            skill="hunt", params={"indicator": {"type": kind, "value": token}}
        )

        assert token in reply["result"]["headline"], reply
        said = " ".join(text for _, text in _strings(reply)).replace("\\", "")
        assert [
            piece for piece in ("example.net", "a_b", "c d", "c%20d", "x=1") if piece in said
        ] == []


@skip_if_dynamic_mode
class TestNameFilter:
    """``name_filter`` is resolved, because one tool takes a device name
    there, and every tool that echoes it returns the caller's own text."""

    async def test_a_device_token_reaches_the_appliance_as_the_device_name(
        self, masked_with_device_identity: tuple[MCPServer, Sweep]
    ) -> None:
        """With device identity masked, a device name only exists as a token
        on the caller's side, and a search by a part of it has to find the
        device."""
        _, sweep = masked_with_device_identity
        token = sweep.tokens["fw-core-01"]

        reply = await sweep.tools["search_devices"](name_filter=token)

        sent = " ".join(sweep.client.seen)
        assert "fw-core-01" in sent
        assert token not in sent
        assert reply["status"] == "success"
        assert _paths_holding(reply, "fw-core-01") == []

    @pytest.mark.parametrize("flag", ["masked", "masked_with_device_identity"])
    async def test_no_tool_that_takes_it_returns_the_plaintext(
        self, flag: str, request: pytest.FixtureRequest
    ) -> None:
        _, sweep = request.getfixturevalue(flag)
        takers = [
            name
            for name, fn in sorted(sweep.tools.items())
            if "name_filter" in inspect.signature(fn).parameters
        ]

        for name in takers:
            await sweep.tool(name)

        assert takers == ["get_alert_handlers", "get_log_fields", "search_devices"]
        assert sweep.unsettled == []
        assert sweep.leaks == []

    async def test_the_echo_of_it_is_the_callers_own_token(
        self, masked: tuple[MCPServer, Sweep]
    ) -> None:
        _, sweep = masked
        token = sweep.tokens["fw-core-01"]

        reply = await sweep.tools["get_log_fields"](logtype="traffic", name_filter=token)

        assert reply["status"] == "success"
        assert reply["name_filter"] == token


@skip_if_dynamic_mode
class TestTheSweepSeesWhatItShould:
    """The guard has to fail for the next argument nobody classified."""

    async def test_it_flags_a_new_parameter_that_echoes_what_it_resolved(
        self, masked: tuple[MCPServer, Sweep]
    ) -> None:
        mcp, sweep = masked

        async def lookup_ticket(ticket: str) -> dict[str, Any]:
            return {"status": "success", "ticket": ticket, "per_ticket": {ticket: 1}}

        await sweep.tool(_register(mcp, sweep, lookup_ticket))

        assert sweep.leaks == [
            "lookup_ticket(ticket) -> $.per_ticket.<key>",
            "lookup_ticket(ticket) -> $.ticket",
        ]

    async def test_it_reaches_a_parameter_of_any_type_a_string_can_arrive_in(
        self, masked: tuple[MCPServer, Sweep]
    ) -> None:
        """The wrapper resolves a token at any depth of a dict or a list, and
        in a parameter with no annotation at all."""
        mcp, sweep = masked

        async def by_options(options: dict[str, Any]) -> dict[str, Any]:
            return {"status": "success", "seen": list(options.values())}

        async def by_anything(ticket: Any) -> dict[str, Any]:
            return {"status": "success", "seen": ticket}

        async def by_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
            return {"status": "success", "seen": [list(row.values()) for row in rows]}

        async def by_unannotated(ticket) -> dict[str, Any]:  # type: ignore[no-untyped-def]
            return {"status": "success", "seen": ticket}

        names = [
            _register(mcp, sweep, fn) for fn in (by_options, by_anything, by_rows, by_unannotated)
        ]
        for name in names:
            await sweep.tool(name)

        assert sweep.never_sent(*names) == {}
        assert sweep.leaks == [
            "by_options(options) -> $.seen[]",
            "by_anything(ticket) -> $.seen",
            "by_rows(rows) -> $.seen[][]",
            "by_unannotated(ticket) -> $.seen",
        ]

    async def test_it_reaches_an_optional_parameter_and_one_with_a_fixed_vocabulary(
        self, masked: tuple[MCPServer, Sweep]
    ) -> None:
        """Most parameters a string can arrive in are optional, and a
        ``Literal`` takes any string on the wire."""
        mcp, sweep = masked

        async def lookup_case(
            case: str | None = None, mode: typing.Literal["fast", "full"] = "fast"
        ) -> dict[str, Any]:
            return {"status": "success", "case": case, "mode": mode}

        name = _register(mcp, sweep, lookup_case)

        assert sorted(sweep.never_sent(name)) == ["lookup_case(case)", "lookup_case(mode)"]
        await sweep.tool(name)
        assert sweep.never_sent(name) == {}
        assert sweep.leaks == ["lookup_case(case) -> $.case", "lookup_case(mode) -> $.mode"]

    async def test_it_flags_a_value_a_substring_filter_respelled(
        self, masked: tuple[MCPServer, Sweep]
    ) -> None:
        """A tool that hands back only a value it had to write for ``like``,
        under a key the output side does not read. One of the values the
        sweep sends has to be such a value, and the comparison has to see it
        behind its backslashes."""
        mcp, sweep = masked

        async def lookup_pattern(ticket: str) -> dict[str, Any]:
            return {"status": "success", "pattern": ticket.replace("_", "\\_") * ("_" in ticket)}

        await sweep.tool(_register(mcp, sweep, lookup_pattern))

        assert sweep.leaks == ["lookup_pattern(ticket) -> $.pattern"]

    async def test_it_sends_every_operator_of_a_filter_condition(
        self, masked: tuple[MCPServer, Sweep]
    ) -> None:
        mcp, sweep = masked
        sent: set[str] = set()

        async def lookup_rows(filters: list[FilterCondition]) -> dict[str, Any]:
            sent.update(condition.op for condition in filters)
            return {"status": "success"}

        await sweep.tool(_register(mcp, sweep, lookup_rows))

        assert sent == set(FILTER_OPS)

    def test_the_comparison_sees_a_value_in_any_spelling_it_is_readable_in(self) -> None:
        assert _paths_holding({"a": "from FW-CORE-01 today"}, "fw-core-01") == ["$.a"]
        assert _paths_holding({"FW-CORE-01": 1}, "fw-core-01") == ["$.<key>"]
        assert _paths_holding({"a": 'user like "%svc\\_bak\\_probe%"'}, "svc_bak_probe") == ["$.a"]
        assert _paths_holding({"a": ["see /a_b/c d?x=1"]}, "/a_b/c%20d?x=1") == ["$.a[]"]
        assert _paths_holding({"a": "svc-bak-probe"}, "svc_bak_probe") == []

    async def test_it_flags_an_echo_of_one_part_of_a_value(
        self, masked: tuple[MCPServer, Sweep]
    ) -> None:
        """Each shape beyond the whole token is what reaches one of these:
        a tool that echoes what stood inside the brackets, and a tool that
        echoes the last word of a phrase."""
        mcp, sweep = masked

        async def lookup_queue(queue: str) -> dict[str, Any]:
            return {"status": "success", "inner": queue.partition("[")[2].rstrip("]")}

        async def lookup_note(note: str) -> dict[str, Any]:
            return {"status": "success", "last": note.rpartition(" ")[2] if " " in note else ""}

        await sweep.tool(_register(mcp, sweep, lookup_queue))
        await sweep.tool(_register(mcp, sweep, lookup_note))

        assert sweep.leaks == ["lookup_queue(queue) -> $.inner", "lookup_note(note) -> $.last"]

    async def test_it_reports_a_parameter_it_could_not_put_a_token_in(
        self, masked: tuple[MCPServer, Sweep]
    ) -> None:
        """A type the sweep cannot fill is a failure, not a parameter that
        passes with no call made."""
        mcp, sweep = masked
        every_shape = sorted(SHAPES)

        async def lookup_blob(
            ticket: str, blob: bytes, limit: int = 5, exact: bool = False
        ) -> dict[str, Any]:
            return {"status": "success"}

        name = _register(mcp, sweep, lookup_blob)

        # Before the sweep, both parameters a string can arrive in are owed.
        assert sweep.never_sent(name) == {
            "lookup_blob(blob)": every_shape,
            "lookup_blob(ticket)": every_shape,
        }
        await sweep.tool(name)
        assert sweep.never_sent(name) == {"lookup_blob(blob)": every_shape}
