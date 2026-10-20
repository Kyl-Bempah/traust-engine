"""The API-based osv adapter: what it collects, and how it reports coverage."""

from collections import Counter

import pytest

from traust_engine.adapters import osv
from traust_engine.osv import BatchOutcome, Query
from traust_engine.portfolio import parsers


def write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.fixture
def repo(tmp_path):
    write(tmp_path, "requirements.txt", "requests==2.19.0\naiohttp[speedups]==3.14.1\n")
    write(tmp_path, "tools/requirements.txt", "flask>=1.0\n")
    write(
        tmp_path,
        "web/package-lock.json",
        '{"name":"w","lockfileVersion":3,"packages":{"":{"name":"w"},'
        '"node_modules/lodash":{"version":"4.17.15"}}}',
    )
    write(tmp_path, "web/package.json", '{"name":"w","dependencies":{"lodash":"^4.17.0"}}')
    write(tmp_path, "web/node_modules/evil/package.json", '{"dependencies":{"x":"1.0.0"}}')
    write(
        tmp_path,
        "go.mod",
        "module example.com/x\n\ngo 1.21\n\ntoolchain go1.21.5\n\n"
        "require golang.org/x/net v0.0.1 // indirect\n",
    )
    write(
        tmp_path,
        "java/pom.xml",
        "<project><groupId>g</groupId><artifactId>a</artifactId><dependencies>"
        "<dependency><groupId>org.x</groupId><artifactId>y</artifactId>"
        "<version>${y.version}</version></dependency></dependencies></project>",
    )
    return tmp_path


def test_requirements_extras_are_parsed():
    _, deps = parsers.parse_requirements_txt("aiohttp[speedups]==3.14.1\nx[a,b] >= 2\n")
    assert ("aiohttp", "3.14.1", False) in deps
    assert ("x", "2", False) in deps


def test_collect_packages(repo):
    packages, stats = osv.collect_packages(repo)
    keys = set(packages)
    assert ("PyPI", "aiohttp", "3.14.1") in keys
    assert packages[("PyPI", "requests", "2.19.0")]["version_basis"] == "locked"
    assert packages[("PyPI", "flask", "1.0")]["version_basis"] == "manifest-floor"
    # the lockfile supersedes package.json in the same directory
    assert packages[("npm", "lodash", "4.17.15")]["version_basis"] == "locked"
    assert ("npm", "lodash", "4.17.0") not in keys
    assert stats["superseded_by_lockfile"] == 1
    # node_modules is never read
    assert not any(k[1] == "x" for k in keys)
    # Go: the leading v is dropped, and the toolchain sets stdlib
    assert ("Go", "golang.org/x/net", "0.0.1") in keys
    assert packages[("Go", "stdlib", "1.21.5")]["version_basis"] == "go-directive"
    # an unresolved Maven property is not a version
    assert not any(k[0] == "Maven" for k in keys)


class FakeClient:
    base_url = "https://osv.test/v1"

    def __init__(self, ids, issues=None, details=None, detail_issues=None):
        self._ids, self._issues = ids, issues or {}
        self._details, self._detail_issues = details or {}, detail_issues or {}

    def query_batch(self, queries):
        return BatchOutcome([self._ids.get(q, []) for q in queries], Counter(self._issues))

    def get_vulns(self, ids):
        return {i: d for i, d in self._details.items() if i in set(ids)}, Counter(
            self._detail_issues
        )


PKGS = {
    ("PyPI", "requests", "2.19.0"): {"sources": ["requirements.txt"], "version_basis": "locked"},
    ("npm", "lodash", "4.17.15"): {"sources": ["web/package-lock.json"], "version_basis": "locked"},
}
VULN = {
    "id": "GHSA-x84v",
    "aliases": ["CVE-2018-18074"],
    "summary": "Credentials leak on redirect",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [
        {
            "package": {"name": "requests", "ecosystem": "PyPI"},
            "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}],
        }
    ],
}


def test_lookup_builds_candidates():
    fake = FakeClient(
        {Query("PyPI", "requests", "2.19.0"): ["GHSA-x84v"]}, details={"GHSA-x84v": VULN}
    )
    candidates, prov = osv.lookup(PKGS, fake)
    assert prov["status"] == "complete"
    (c,) = candidates
    assert c["osv_id"] == "GHSA-x84v"
    assert c["fixed_version"] == "2.20.0"
    assert c["max_severity"] == "9.8"
    assert c["version_basis"] == "locked"
    assert c["details_fetched"] is True
    assert osv._cvss_to_severity(c["max_severity"]) == "critical"


def test_unanswered_lookups_make_the_scan_degraded():
    class Partial(FakeClient):
        def query_batch(self, queries):
            ids = [None if q.ecosystem == "npm" else [] for q in queries]
            return BatchOutcome(ids, Counter({"unreachable": 1}))

    candidates, prov = osv.lookup(PKGS, Partial({}))
    assert candidates == []
    assert prov["status"] == "degraded"
    assert prov["packages_unanswered"] == 1
    assert prov["lookup_issues"] == {"unreachable": 1}


def test_a_missing_advisory_detail_keeps_the_candidate():
    fake = FakeClient(
        {Query("PyPI", "requests", "2.19.0"): ["GHSA-x84v"]}, detail_issues={"unreachable": 1}
    )
    candidates, prov = osv.lookup(PKGS, fake)
    assert [c["osv_id"] for c in candidates] == ["GHSA-x84v"]
    assert candidates[0]["details_fetched"] is False
    assert prov["status"] == "degraded"
    assert prov["advisory_details_missing"] == 1


@pytest.mark.parametrize(
    ("value", "band"),
    [
        ("9.8", "critical"),
        ("7.5", "high"),
        ("5.3", "medium"),
        ("2.0", "low"),
        ("HIGH", "high"),
        (None, "medium"),
    ],
)
def test_numeric_scores_are_banded(value, band):
    assert osv._cvss_to_severity(value) == band
