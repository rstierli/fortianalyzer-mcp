"""Contract tests for the server-level ``instructions`` block.

``MCPServer(instructions=...)`` is the only text this server ships that a
client reads *before* choosing a tool. Per-tool docstrings cannot carry a
cross-cutting fact, because a caller holding one tool's docstring has no
reason to suspect a neighbouring tool disagrees -- and here several do.

The fact these tests exist to protect is the **tid taxonomy**. Five tool
families return something spelled ``tid``, and the values are not
interchangeable:

* ``query_logs`` -> an int that is a *reusable pagination handle*, not the
  appliance task id (the appliance reaps that after one fetch).
* ``run_fortiview`` -> an int appliance task id, one-shot, and only valid
  when re-paired with the same ``view_name``.
* ``run_report`` -> a UUID *string*, not an int.
* ``run_ioc_rescan`` -> an int appliance task id of a different job type.
* ``search_ips_logs`` -> a vestigial echo of a reaped id; not usable at all.

A caller that generalises "I hold a tid, so I can page it" from the first
to any of the others gets confusing failures. That is the misuse this
block prevents, so a change that drops a family from it is a regression
even though no code path breaks.

Assertions target tool names and operator tokens rather than prose, so the
wording stays free to change while the load-bearing facts cannot silently
go missing.
"""

import importlib

import pytest

#: Each async family that hands back a value spelled ``tid``, mapped to the
#: tools that consume it. Every name here must appear in the instructions:
#: a family absent from the taxonomy is a family a caller will guess about.
TID_FAMILIES = {
    "query_logs": ("fetch_more_logs", "cancel_log_search"),
    "run_fortiview": ("fetch_fortiview",),
    "run_report": ("fetch_report", "get_report_data"),
    "run_ioc_rescan": ("get_ioc_rescan_status",),
    "search_ips_logs": (),
}

#: The FortiAnalyzer filter grammar the server itself emits. The raw
#: ``filter`` string remains an escape hatch, so the operator set belongs
#: where it is read up front. Substring matching emits ``like`` on both
#: dialects: the appliance accepts ``contain``/``!contain`` and then silently
#: matches zero rows, so neither is emitted any more and neither belongs here.
FILTER_OPERATORS = ("==", "!=", "<=", ">=", "like")

#: The ``filters`` op vocabulary. This is the surface a caller must get
#: right, and it is validated locally, so it is the more load-bearing list.
STRUCTURED_FILTER_OPS = (
    "eq",
    "ne",
    "gt",
    "gte",
    "lt",
    "lte",
    "contains",
    "not_contains",
    "in",
    "not_in",
)


@pytest.fixture(scope="module")
def instructions() -> str:
    """The live ``instructions`` string off the module-global MCPServer."""
    server = importlib.import_module("fortianalyzer_mcp.server")
    text = server.mcp.instructions
    assert text is not None, "MCPServer was constructed without instructions="
    return text


def test_server_declares_instructions(instructions: str) -> None:
    """The server ships a usage guide at all.

    Without this, a client sees 86 tool docstrings and no arbitration
    between them.
    """
    assert instructions.strip(), "instructions= is present but empty"


@pytest.mark.parametrize("starter", sorted(TID_FAMILIES))
def test_instructions_name_every_tid_starter(instructions: str, starter: str) -> None:
    """Every tool that *hands out* a tid is named in the taxonomy."""
    assert starter in instructions, f"{starter} returns a tid but is undocumented"


@pytest.mark.parametrize(
    "consumer",
    sorted(name for consumers in TID_FAMILIES.values() for name in consumers),
)
def test_instructions_name_every_tid_consumer(instructions: str, consumer: str) -> None:
    """Every tool that *takes* a tid is named, paired with its starter."""
    assert consumer in instructions, f"{consumer} consumes a tid but is undocumented"


def test_instructions_mark_the_logsearch_tid_as_a_reusable_handle(instructions: str) -> None:
    """The query_logs tid must be distinguished from an appliance task id.

    This is the single most misusable fact in the server: the value is a
    local pagination handle, so it survives repeated use, while every
    other tid does not.
    """
    assert "reusable" in instructions.lower()


def test_instructions_mark_the_ips_tid_as_unusable(instructions: str) -> None:
    """search_ips_logs' tid is shape-identical to a handle but is inert."""
    lowered = instructions.lower()
    assert "vestigial" in lowered or "not usable" in lowered


def test_instructions_state_the_report_tid_is_a_string(instructions: str) -> None:
    """run_report breaks the int assumption every other family sets."""
    assert "uuid" in instructions.lower()


@pytest.mark.parametrize("operator", FILTER_OPERATORS)
def test_instructions_document_the_filter_operator_set(instructions: str, operator: str) -> None:
    """The filter grammar is stated up front, not only on failure."""
    assert operator in instructions, f"filter operator {operator!r} undocumented"


def test_instructions_point_large_result_sets_at_the_aggregation_tools(
    instructions: str,
) -> None:
    """A caller facing 100k rows should be steered off raw paging.

    analyze_policy_traffic (successor to the retired policy trio) and
    query_logs's own group_by/sample_by pre-aggregate server-side and are
    honest about exactness; paging 100k rows through an LLM context is never
    the right answer to a volume question.
    """
    assert "analyze_policy_traffic" in instructions


def test_instructions_document_the_field_trim_escape_hatch(instructions: str) -> None:
    """list_adoms/list_devices default to every field; say so.

    The ``fields`` parameter has always existed on both. A reviewer with
    live access still concluded ``list_devices`` had none, which is
    precisely the cost of leaving it undocumented here.
    """
    assert "fields" in instructions
    assert "list_adoms" in instructions
    assert "list_devices" in instructions


@pytest.mark.parametrize("op", STRUCTURED_FILTER_OPS)
def test_structured_filter_ops_are_documented(instructions: str, op: str) -> None:
    """The op vocabulary is what a caller must get right; freeze it."""
    assert op in instructions, f"op {op!r} missing from the usage guide"


def test_filters_parameter_is_named(instructions: str) -> None:
    assert "filters" in instructions


def test_in_is_caveated_for_the_array_dialect_tools(instructions: str) -> None:
    """``in`` hard-errors on search_devices/list_tasks (compile_to_array
    refuses it), so a guide listing ``in`` unqualified beside "the same
    filters parameter" promises an op that fails on two of its consumers.
    The remedy phrase is asserted because it matches the error the caller
    would otherwise hit blind.
    """
    assert "search_devices" in instructions
    assert "list_tasks" in instructions
    assert "one call per value" in instructions


def test_unverified_operators_are_not_advertised(instructions: str) -> None:
    """regex/isnull are documented by Fortinet but unproven through the API
    here, so the guide must not promise them.

    Naming them even as "unverified" puts them in front of a model that will
    then try them, so the guide states the boundary without the vocabulary.

    ``like`` used to be on this list and is deliberately no longer: it is now
    the *emitted* substring operator on both dialects, proven on 7.6.6, 7.6.7
    and 8.0.0, because the documented ``contain`` spelling is accepted by the
    parser and silently matches zero rows. See ``FILTER_OPERATORS``.
    """
    for token in ("isnull", "isnotnull", "=~", "!~"):
        assert token not in instructions


def test_the_working_negation_form_is_shown_not_just_named(instructions: str) -> None:
    """``not like`` is rejected live with ``Invalid filter`` on 7.6.6, so a
    caller writing the obvious negation gets an error rather than rows.

    The guide therefore has to show the wrapped form, because there is no way
    to derive ``!(field like "%x%")`` from knowing that ``like`` works.
    """
    assert '!(service like "%DNS%")' in instructions
    assert "not like" in instructions


class TestMaskingGuidance:
    """The masking section ships only when masking is actually on.

    Two separate risks. If the text is missing when masking IS on, the model
    receives format-preserving tokens with nothing telling it they are tokens,
    and a token that looks like an odd hostname invites being "corrected" --
    which resolves to nothing. If the text is present when masking is OFF, every
    handshake pays for advice about values this server will never emit, in a
    guide whose whole discipline is earning its context budget back.
    """

    def test_default_guide_says_nothing_about_masking(self, instructions: str) -> None:
        """Masking is off by default, so the live guide must be the plain one."""
        from fortianalyzer_mcp.instructions import SERVER_INSTRUCTIONS

        assert instructions == SERVER_INSTRUCTIONS
        assert "masking enabled" not in instructions

    def test_masking_off_returns_the_guide_unchanged(self) -> None:
        from fortianalyzer_mcp.instructions import SERVER_INSTRUCTIONS, build_instructions

        assert build_instructions(masking_enabled=False) == SERVER_INSTRUCTIONS

    def test_masking_on_appends_the_section(self) -> None:
        from fortianalyzer_mcp.instructions import SERVER_INSTRUCTIONS, build_instructions

        text = build_instructions(masking_enabled=True)
        assert text.startswith(SERVER_INSTRUCTIONS)
        assert len(text) > len(SERVER_INSTRUCTIONS)

    def test_the_section_says_to_pass_tokens_back_unchanged(self) -> None:
        """The load-bearing instruction: a token is the handle, so editing one
        destroys it. Deterministic FPE means the token IS the identity."""
        from fortianalyzer_mcp.instructions import build_instructions

        text = build_instructions(masking_enabled=True).lower()
        assert "exactly as received" in text
        assert "deterministic" in text

    def test_the_section_names_contains_as_the_filter_operator(self) -> None:
        """Measured on live 7.6.6: dvmdb ``like`` is case-insensitive while
        ``==`` is case-sensitive, and token alphabets are lowercase. So ``eq``
        on a round-tripped device identifier returns ``count: 0`` with
        ``status: "success"`` -- indistinguishable from "no such device" --
        while ``contains`` matches. Naming the operator is the whole point;
        a generic "tokens are lowercase" warning does not tell a caller what
        to do instead.
        """
        from fortianalyzer_mcp.instructions import build_instructions

        text = build_instructions(masking_enabled=True)
        assert '`op: "contains"`' in text
        assert "case-sensitive" in text
        # The failure mode is named, so the caller can recognise it when seen.
        assert "zero rows" in text


def test_projection_surface_is_documented(instructions: str) -> None:
    """A caller who does not know `fields` exists pays for every key."""
    assert "fields" in instructions
    assert '["*"]' in instructions or '"*"' in instructions


def test_curated_default_is_described_as_a_default_not_a_limit(
    instructions: str,
) -> None:
    """The opt-out must be discoverable in the same breath as the default."""
    lowered = instructions.lower()
    assert "curated" in lowered


def test_the_projection_tool_list_matches_the_tools_that_actually_take_fields(
    instructions: str,
) -> None:
    """The guide named the surface wrong in both directions before this.

    It claimed "Every read tool takes `fields`" when 15 of ~85 do -- and the
    ones an LLM reaches for most (get_top_*, list_tasks, get_alert_details,
    get_incident) still do not. An overclaim here is worse than silence: it
    sends the model to spend a call discovering a parameter that is not there.

    Derived from the tool signatures rather than from a second hand-written
    list, so adding or removing a `fields` parameter fails this test until the
    guide is updated with it.
    """
    import ast
    import pathlib

    import fortianalyzer_mcp.tools as tools_pkg

    root = pathlib.Path(next(iter(tools_pkg.__path__)))
    taking_fields = {
        node.name
        for path in root.glob("*.py")
        for node in ast.walk(ast.parse(path.read_text()))
        if isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef)
        and "fields" in {a.arg for a in node.args.args + node.args.kwonlyargs}
    }

    assert taking_fields, "sanity: some tool must take fields"
    missing = sorted(name for name in taking_fields if name not in instructions)
    assert not missing, f"the usage guide does not name these fields-taking tools: {missing}"
    assert str(len(taking_fields)) in instructions, (
        f"{len(taking_fields)} tools take fields; the guide states a different count"
    )


def test_the_guide_does_not_claim_every_read_tool_takes_fields(instructions: str) -> None:
    """The specific overclaim, frozen so it cannot come back."""
    assert "Every read tool takes" not in instructions


def test_response_size_and_projection_do_not_contradict_each_other(instructions: str) -> None:
    """Two sections, six lines apart, said opposite things about the default.

    ``## Projection`` said the default is curated; ``## Response size`` said
    list_adoms and list_devices "return every field by default". Both were
    true of different tools, which is exactly what made the pair read as a
    contradiction. The reconciliation is that the tools with no curated
    default are named as such in both places.
    """
    assert "return every field by default" not in instructions
    projection = instructions.split("## Projection")[1].split("## Choosing")[0]
    assert "no curated default" in projection
    assert "list_adoms and list_devices have no curated default" in instructions


AGGREGATION_PARAMETERS = ("group_by", "sample_by", "count_only", "top_n")

CONSOLIDATED_TOOLS = (
    "get_fortiview_data",
    "analyze_policy_traffic",
    "query_logs",
)

REMOVED_TOOL_NAMES = (
    "get_top_sources",
    "get_top_destinations",
    "get_top_applications",
    "get_top_threats",
    "get_top_websites",
    "get_top_cloud_applications",
    "get_policy_hits",
    "search_traffic_logs",
    "search_security_logs",
    "search_event_logs",
    "get_policy_traffic_profile",
    "get_policy_port_analysis",
    "get_policy_protocol_summary",
)


@pytest.mark.parametrize("parameter", AGGREGATION_PARAMETERS)
def test_aggregation_parameters_are_documented(instructions: str, parameter: str) -> None:
    assert parameter in instructions, f"{parameter} missing from the usage guide"


@pytest.mark.parametrize("name", CONSOLIDATED_TOOLS)
def test_the_surviving_tools_are_named(instructions: str, name: str) -> None:
    assert name in instructions


@pytest.mark.parametrize("name", REMOVED_TOOL_NAMES)
def test_removed_tools_are_not_recommended(instructions: str, name: str) -> None:
    """A guide that still names a deleted tool sends every client to an error."""
    assert name not in instructions, f"{name} was removed but is still recommended"


def test_the_exactness_split_is_stated(instructions: str) -> None:
    """group_by exact, sample_by bounded -- the reason there are two names."""
    lowered = instructions.lower()
    assert "exact" in lowered
    assert "sample" in lowered
