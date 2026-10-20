"""CVSS v3.x base score from a vector string (FIRST CVSS v3.1 specification).

OSV records carry CVSS vectors, not scores. osv-scanner computed a score;
the API-based adapter does it here. v2 and v4 vectors return ``None``.
"""

from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: smallest one-decimal number >= value."""
    i = round(value * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def base_score(vector: str) -> float | None:
    """Base score for a ``CVSS:3.0/...`` or ``CVSS:3.1/...`` vector, else ``None``."""
    if not vector or not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    try:
        metrics = dict(part.split(":", 1) for part in vector.split("/")[1:])
        scope_changed = metrics["S"] == "C"
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"]]
        iss = 1 - ((1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]]))
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        exploitability = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * pr * _UI[metrics["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def max_score(vuln: dict) -> float | None:
    """Highest v3 base score among an OSV record's ``severity`` entries."""
    scores = [
        s
        for entry in vuln.get("severity") or []
        if isinstance(entry, dict)
        for s in [base_score(str(entry.get("score") or ""))]
        if s is not None
    ]
    for affected in vuln.get("affected") or []:
        for entry in (affected or {}).get("severity") or []:
            if isinstance(entry, dict):
                s = base_score(str(entry.get("score") or ""))
                if s is not None:
                    scores.append(s)
    return max(scores) if scores else None
