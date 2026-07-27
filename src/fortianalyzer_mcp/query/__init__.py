"""Pure query-shaping layer: vocabularies, filter compilation, response shaping.

Everything here is data and pure functions. No module in this package imports a
client, ``server``, or anything from ``tools`` -- so it cannot take part in the
import-time registration order that ``server.py``'s bottom import block relies
on, and it is testable without an appliance.

The two compilers exist because FortiAnalyzer speaks two filter dialects: the
string grammar (logview, fortiview, eventmgmt, incidentmgmt) and the
``[field, op, value]`` array (dvmdb, config, task). A tool names the dialect its
endpoint speaks; it never hand-builds a filter.
"""

from fortianalyzer_mcp.query.fields import (
    TASK_STATE_CODES,
    Vocabulary,
    canonical_log_field,
    coerce_value,
    get_vocabulary,
    resolve_field,
)
from fortianalyzer_mcp.query.filters import (
    FilterCondition,
    FilterOp,
    compile_to_array,
    compile_to_string,
)

__all__ = [
    "TASK_STATE_CODES",
    "FilterCondition",
    "FilterOp",
    "Vocabulary",
    "canonical_log_field",
    "coerce_value",
    "compile_to_array",
    "compile_to_string",
    "get_vocabulary",
    "resolve_field",
]
