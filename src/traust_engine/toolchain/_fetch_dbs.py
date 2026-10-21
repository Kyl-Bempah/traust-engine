"""Populate tool vulnerability DBs.

Usage (standalone):
    python3 -m traust_engine.toolchain._fetch_dbs --tools grype

For profile-based usage, use the CLI layer which owns the manifest:
    python3 -m traust.cli.toolchain fetch-dbs --profile secure-code-audit

osv-scanner is not here: OSV is queried through its API, and an air-gapped
deployment's offline OSV database is provided by the adopter, never fetched
by the harness (owner decision 2026-10-20).
"""

from __future__ import annotations

import subprocess

from traust_engine.toolchain._parsers import db_status

_POPULATE_CMDS: dict[str, list[list[str]]] = {
    "grype": [["grype", "db", "update"]],
}

POPULATABLE_TOOLS: frozenset[str] = frozenset(_POPULATE_CMDS)


def populate(tool_name: str) -> tuple[bool, str]:
    """Run the DB populate command for *tool_name*.

    Returns (success, message).
    """
    cmds = _POPULATE_CMDS.get(tool_name)
    if cmds is None:
        return True, f"{tool_name}: no DB to populate"

    for cmd in cmds:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if proc.returncode != 0:
                err = proc.stderr.strip()[:500]
                return False, (
                    f"{tool_name}: {' '.join(cmd)} failed (exit {proc.returncode}): {err}"
                )
        except FileNotFoundError:
            return False, f"{tool_name}: {cmd[0]} not found on PATH"
        except subprocess.TimeoutExpired:
            return False, f"{tool_name}: {' '.join(cmd)} timed out"

    info = db_status(tool_name)
    built = info.built if info else "unknown"
    return True, f"{tool_name}: DB populated (built {built})"
