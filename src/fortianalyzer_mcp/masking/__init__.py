"""Reversible data masking for LLM-bound IOC data (RFC #40).

Phase 0: the FPE token engine.
Phase 1 (prototype): field allowlist + tool-boundary output masking.
Later phases add tool-argument unmasking and configuration hardening.
"""

from fortianalyzer_mcp.masking.fpe_engine import FPEEngine, MaskingError
from fortianalyzer_mcp.masking.wrapper import OutputMasker, install_masking

__all__ = ["FPEEngine", "MaskingError", "OutputMasker", "install_masking"]
