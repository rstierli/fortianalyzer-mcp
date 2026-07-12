"""FortiAnalyzer MCP skills layer (RFC #44).

Opinionated multi-tool orchestrations that sit above the raw tools and
return validated, structured results. Exposed through a single dispatcher
tool (``faz_skill``) so the tool surface grows by exactly one entry no
matter how many skills exist.

Feature-flagged: nothing in this package is registered unless
``FAZ_SKILLS_ENABLED`` is true (default off). Wave 1 skills compose
existing read-only tools only; they perform no writes.
"""
