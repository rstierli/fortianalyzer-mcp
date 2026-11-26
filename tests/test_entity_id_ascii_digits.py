"""An entity id is ASCII digits (#187 item A10).

hunt and investigate_deep parse ``epid:N`` / ``euid:N`` with ``isdigit()``
and then ``int()``. ``isdigit()`` is also true for digits ``int()`` does not
read, such as a superscript two, so such an id raised ValueError inside the
handler and the dispatcher answered ``skill_error``, where a malformed id
gives ``skill_failed``. The check is now ``isascii() and isdigit()``. That
also refuses decimal digits of other scripts, which ``int()`` would have
read as a number.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from tests.conftest import import_dispatcher_isolated

(faz_skill,) = import_dispatcher_isolated("faz_skill")

QUERY_LOGS = "fortianalyzer_mcp.tools.log_tools.query_logs"
GET_ENDPOINTS = "fortianalyzer_mcp.tools.ueba_tools.get_endpoints"
GET_ENDUSERS = "fortianalyzer_mcp.tools.ueba_tools.get_endusers"

SUPERSCRIPT_TWO = "²"
ARABIC_INDIC_TWELVE = "١٢"

CASES = [
    ("hunt", "epid", "entity must be 'epid:N' or 'euid:N'"),
    ("hunt", "euid", "entity must be 'epid:N' or 'euid:N'"),
    ("investigate_deep", "epid", "entity 'epid:' expects a numeric id"),
    ("investigate_deep", "euid", "entity 'euid:' expects a numeric id"),
]


@pytest.mark.parametrize(("skill", "kind", "refusal"), CASES)
@pytest.mark.parametrize(
    "digits", [SUPERSCRIPT_TWO, ARABIC_INDIC_TWELVE], ids=["superscript", "arabic-indic"]
)
async def test_a_non_ascii_digit_id_is_a_malformed_id(
    skill: str, kind: str, refusal: str, digits: str
) -> None:
    ok: dict[str, Any] = {"status": "success", "data": []}
    with (
        patch(QUERY_LOGS, autospec=True) as logs,
        patch(GET_ENDPOINTS, autospec=True, return_value=ok) as endpoints,
        patch(GET_ENDUSERS, autospec=True, return_value=ok) as endusers,
    ):
        result = await faz_skill(skill=skill, params={"entity": f"{kind}:{digits}"})

    assert result["status"] == "error"
    assert result["error"] == "skill_failed"
    assert result["message"] == refusal
    for read in (logs, endpoints, endusers):
        read.assert_not_called()
