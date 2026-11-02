"""Dependency declarations that must match what the server actually uses."""

import tomllib
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_PYPROJECT = _ROOT / "pyproject.toml"


def _requirement(prefix: str) -> str:
    data = tomllib.loads(_PYPROJECT.read_text())
    for entry in data["project"]["dependencies"]:
        if entry.startswith(prefix):
            return entry
    raise AssertionError(f"{prefix} is not declared in pyproject dependencies")


def test_security_floors_are_declared() -> None:
    """Nothing upstream raises these to the patched releases.

    Measured against mcp 2.3.0: mcp does not depend on pydantic-settings at
    all, and the tightest starlette constraint in the tree is
    ``sse-starlette`` 3.6.0's ``>=0.49.1`` (mcp itself asks ``>=0.27``, or
    ``>=0.48.0`` on 3.14+). pydantic-settings 2.14.2 fixes
    GHSA-4xgf-cpjx-pc3j and starlette 1.3.1 fixes PYSEC-2026-249. Twin of
    rstierli/fortimanager-mcp#38.
    """
    assert _requirement("pydantic-settings") == "pydantic-settings>=2.14.2"
    assert _requirement("starlette") == "starlette>=1.3.1"


def test_httpx_is_not_declared() -> None:
    """mcp 2.x depends on ``httpx2``, never ``httpx``.

    Nothing in ``src/`` or ``tests/`` imports ``httpx``, and nothing else
    in the tree pulls it: starlette wants it only under a ``full`` extra
    this project does not install. Twin of rstierli/fortimanager-mcp#95.
    """
    data = tomllib.loads(_PYPROJECT.read_text())
    # Match the name exactly. A bare ``startswith("httpx")`` would also fire
    # on a future ``httpx2`` floor.
    declared = [
        e
        for e in data["project"]["dependencies"]
        if e == "httpx"
        or e.startswith(("httpx>", "httpx=", "httpx<", "httpx!", "httpx~", "httpx["))
    ]
    assert declared == [], f"httpx is declared but unused: {declared}"


def test_noise_suppression_names_the_client_that_ships() -> None:
    """The suppression must name ``httpx2``, the client mcp 2.x actually uses.

    Under mcp 1.x this named ``httpx``; 2.x logs under ``httpx2``
    (``httpx2/_client.py``), so the old name silenced a logger this tree
    no longer has.
    """
    source = (_ROOT / "src" / "fortianalyzer_mcp" / "utils" / "config.py").read_text()
    assert 'getLogger("httpx2")' in source
    assert 'getLogger("httpx")' not in source
