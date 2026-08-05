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
    has_projection,
    resolve_field,
)
from fortianalyzer_mcp.query.filters import (
    FilterCondition,
    FilterOp,
    compile_to_array,
    compile_to_string,
)
from fortianalyzer_mcp.query.groups import (
    LOG_GROUP_SURFACES,
    VIEW_SORT_DEFAULTS,
    GroupPlan,
    GroupSurfacePopulationMismatch,
    LogGroupSurface,
    UnsupportedGroupDimension,
    aggregate_breakdowns,
    resolve_group_plan,
)
from fortianalyzer_mcp.query.shape import (
    ALL_FIELDS,
    fields_returned,
    project_payload,
    project_rows,
    resolve_projection,
)

__all__ = [
    "ALL_FIELDS",
    "LOG_GROUP_SURFACES",
    "VIEW_SORT_DEFAULTS",
    "TASK_STATE_CODES",
    "FilterCondition",
    "FilterOp",
    "GroupPlan",
    "GroupSurfacePopulationMismatch",
    "LogGroupSurface",
    "UnsupportedGroupDimension",
    "Vocabulary",
    "aggregate_breakdowns",
    "canonical_log_field",
    "coerce_value",
    "compile_to_array",
    "compile_to_string",
    "fields_returned",
    "get_vocabulary",
    "has_projection",
    "project_payload",
    "project_rows",
    "resolve_field",
    "resolve_group_plan",
    "resolve_projection",
]
