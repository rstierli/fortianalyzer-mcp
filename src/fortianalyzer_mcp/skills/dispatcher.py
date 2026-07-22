"""The ``faz_skill`` dispatcher tool.

One MCP tool routes to every skill in the catalogue: parameters are
validated against the skill's pydantic model, the handler runs, and the
output model is validated before anything is returned — a validation
failure is a skill error, never a malformed passthrough.

This module is imported (and the tool registered) only when
``FAZ_SKILLS_ENABLED`` is true; see ``server.py``.
"""

import logging
from typing import Any

from pydantic import ValidationError

from fortianalyzer_mcp.server import mcp
from fortianalyzer_mcp.skills.catalog import SKILLS, catalogue
from fortianalyzer_mcp.skills.handlers import SkillExecutionError
from fortianalyzer_mcp.skills.models import SCHEMA_VERSION
from fortianalyzer_mcp.utils.responses import error_response, redact

logger = logging.getLogger(__name__)

_SKILL_IDS = ", ".join(sorted(SKILLS))


def _redact_warnings(node: Any) -> Any:
    """Redact every ``warnings`` list of strings in ``node``, at any depth.

    Reading the top-level key alone was enough while every skill returned a
    flat result. A skill that composes other skills is not flat: each
    composed section keeps its own ``warnings``, and the composing handler
    copies them upward with a section prefix. Only the copies were reaching
    the chokepoint, so each warning shipped twice, once scrubbed and once
    verbatim. Whichever of the two an operator reads is a coin toss, which
    is the same as not scrubbing at all.

    Only ``warnings`` is rewritten, and only its string elements, so no
    other field shape is touched. See issue #68 M4 for why this scrubbing
    exists at all.
    """
    if isinstance(node, dict):
        return {
            key: [redact(item) if isinstance(item, str) else item for item in value]
            if key == "warnings" and isinstance(value, list)
            else _redact_warnings(value)
            for key, value in node.items()
        }
    if isinstance(node, list):
        return [_redact_warnings(item) for item in node]
    return node


@mcp.tool()
async def faz_skill(skill: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run a FortiAnalyzer skill: an opinionated multi-tool orchestration
    returning a validated, structured result.

    Available skills (pass as ``skill``): ``incidents`` (incidents +
    correlated alerts), ``reports`` (list/fetch generated reports),
    ``log_search`` (filter-based search, verbatim rows), ``triage``
    (alert/incident evidence bundle + deterministic assessment),
    ``incident_summary`` (structured incident investigation summary).

    Pass ``skill="list"`` (alias: ``skill="describe"``) to get the full
    catalogue including each skill's parameter and output JSON schema.
    Skill parameters go in ``params`` (a dict validated against the
    skill's schema; unknown keys are rejected).

    All skills are read-only. Output schemas are versioned
    (``schema_version`` in every response) and stable across releases.
    """
    if skill in ("list", "describe"):
        return {
            "status": "success",
            "schema_version": SCHEMA_VERSION,
            "skills": catalogue(),
        }

    spec = SKILLS.get(skill)
    if spec is None:
        return error_response(
            error="unknown_skill",
            message=f"unknown skill {skill!r}; available: {_SKILL_IDS} (or 'list')",
            operation="faz_skill",
        )

    try:
        parsed = spec.params_model(**(params or {}))
    except ValidationError as exc:
        return error_response(
            error="invalid_skill_params",
            message=redact(str(exc)),
            operation="faz_skill",
            skill=skill,
        )

    try:
        result = await spec.handler(parsed)
    except SkillExecutionError as exc:
        return error_response(
            error="skill_failed",
            message=redact(str(exc)),
            operation="faz_skill",
            skill=skill,
        )
    except ValidationError as exc:
        # The handler produced data that violates the documented output
        # contract — surface it as an error, never as a malformed result.
        logger.error("skill %s output failed schema validation: %s", skill, exc)
        return error_response(
            error="skill_output_invalid",
            message=redact(str(exc)),
            operation="faz_skill",
            skill=skill,
        )
    except Exception as exc:
        logger.exception("skill %s raised unexpectedly", skill)
        return error_response(
            error="skill_error",
            message=redact(str(exc)),
            operation="faz_skill",
            skill=skill,
        )

    # The success path does not go through error_response, so scrub the
    # caller-facing warnings here too: a degraded sub-call can carry raw FAZ
    # exception text (internal hostnames, session/token material) into a
    # warning. Redacting at the source covers today's warnings; this is the
    # belt-and-suspenders chokepoint for any warning shape. See issue #68 M4.
    dumped = _redact_warnings(result.model_dump())
    return {
        "status": "success",
        "skill": skill,
        "schema_version": SCHEMA_VERSION,
        "result": dumped,
    }
