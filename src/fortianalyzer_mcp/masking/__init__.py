"""Reversible data masking for LLM-bound IOC data (RFC #40).

Phase 0: the FPE token engine. Later phases add the tool-boundary
mask/unmask wrapper and configuration wiring.
"""

from fortianalyzer_mcp.masking.fpe_engine import FPEEngine, MaskingError

__all__ = ["FPEEngine", "MaskingError"]
