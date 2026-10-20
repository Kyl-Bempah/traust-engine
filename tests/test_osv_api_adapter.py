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
    probe_failure = None

    def probe(self, query):
        return self.probe_failure

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


def test_severity_is_borrowed_from_a_ghsa_alias():
    go_vuln = {
        "id": "GO-2026-1",
        "aliases": ["GHSA-abcd"],
        "affected": [{"package": {"name": "github.com/x/y", "ecosystem": "Go"}}],
    }
    ghsa = {
        "id": "GHSA-abcd",
        "database_specific": {"severity": "HIGH"},
        "severity": VULN["severity"],
    }
    pkgs = {("Go", "github.com/x/y", "1.0.0"): {"sources": ["go.mod"], "version_basis": "locked"}}
    fake = FakeClient(
        {Query("Go", "github.com/x/y", "1.0.0"): ["GO-2026-1"]},
        details={"GO-2026-1": go_vuln, "GHSA-abcd": ghsa},
    )
    candidates, prov = osv.lookup(pkgs, fake)
    assert candidates[0]["max_severity"] == "9.8"
    assert prov["status"] == "complete"


YARN_V1 = """# yarn lockfile v1


"@algolia/autocomplete-core@1.5.2", "@algolia/autocomplete-core@^1.5.0":
  version "1.5.2"
  dependencies:
    "@algolia/autocomplete-shared" "1.5.2"

lodash@^4.17.0:
  version "4.17.15"
"""

YARN_BERRY = """__metadata:
  version: 8

"@aashutoshrathi/word-wrap@npm:^1.2.3":
  version: 1.2.6
  resolution: "@aashutoshrathi/word-wrap@npm:1.2.6"

"my-app@workspace:.":
  version: 0.0.0-use.local

"string-width-cjs@npm:string-width@^4.2.0":
  version: 4.2.3

"@material-ui/pickers@patch:@material-ui/pickers@npm%3A3.3.11#./x.patch::locator=root":
  version: 3.3.11
"""


def test_yarn_classic():
    _, deps = parsers.parse_yarn_lock(YARN_V1)
    assert deps == [("@algolia/autocomplete-core", "1.5.2", True), ("lodash", "4.17.15", True)]


def test_yarn_berry_skips_workspaces_and_resolves_aliases():
    _, deps = parsers.parse_yarn_lock(YARN_BERRY)
    assert ("@aashutoshrathi/word-wrap", "1.2.6", True) in deps
    assert ("string-width", "4.2.3", True) in deps  # alias resolved to the real package
    assert (
        "@material-ui/pickers",
        "3.3.11",
        True,
    ) in deps  # a patched package is still that package
    assert not any(
        name == "my-app" for name, _, _ in deps
    )  # the workspace itself is not a dependency


def test_yarn_lock_is_a_lockfile(tmp_path):
    write(tmp_path, "yarn.lock", YARN_V1)
    write(tmp_path, "package.json", '{"dependencies":{"lodash":"^4.0.0"}}')
    packages, stats = osv.collect_packages(tmp_path)
    assert packages[("npm", "lodash", "4.17.15")]["version_basis"] == "locked"
    assert ("npm", "lodash", "4.0.0") not in packages
    assert stats["superseded_by_lockfile"] == 1


def test_uv_lock_skips_workspace_members():
    text = """version = 1

[[package]]
name = "absl-py"
version = "2.4.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "MLflow"
version = "3.0.0.dev0"
source = { editable = "." }

[[package]]
name = "Some_Pkg"
version = "1.2.3"
source = { git = "https://github.com/x/y?rev=abc" }
"""
    _, deps = parsers.parse_uv_lock(text)
    assert deps == [("absl-py", "2.4.0", True), ("some-pkg", "1.2.3", True)]


@pytest.mark.parametrize(
    "name",
    [
        "requirements.txt",
        "requirements-dev.txt",
        "dev-requirements.txt",
        "py3.10-ci-requirements.txt",
    ],
)
def test_requirements_files_are_found_by_any_name(name):
    assert parsers.parser_for(f"sdk/{name}")[0] == "pypi"


def test_severity_basis_is_recorded():
    fake = FakeClient(
        {Query("PyPI", "requests", "2.19.0"): ["GHSA-x84v"]}, details={"GHSA-x84v": VULN}
    )
    (c,), _ = osv.lookup(PKGS, fake)
    assert c["severity_basis"] == "cvss-v3"


def test_an_unscored_advisory_is_labelled_not_guessed():
    bare = {"id": "PYSEC-1", "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"}}]}
    fake = FakeClient({Query("PyPI", "requests", "2.19.0"): ["PYSEC-1"]}, details={"PYSEC-1": bare})
    (c,), _ = osv.lookup(PKGS, fake)
    assert c["max_severity"] is None
    assert c["severity_basis"] == "unscored"
    assert osv._cvss_to_severity(c["max_severity"]) == "medium"  # the harness rule, labelled


def test_a_malicious_package_is_critical():
    mal = {"id": "MAL-2025-1", "affected": [{"package": {"name": "lodash", "ecosystem": "npm"}}]}
    fake = FakeClient(
        {Query("npm", "lodash", "4.17.15"): ["MAL-2025-1"]}, details={"MAL-2025-1": mal}
    )
    (c,), _ = osv.lookup(PKGS, fake)
    assert c["severity_basis"] == "malicious-package"
    assert osv._cvss_to_severity(c["max_severity"]) == "critical"


def test_manifests_without_a_lockfile_are_a_coverage_gap(repo):
    _, stats = osv.collect_packages(repo)
    unresolved = {m["path"] for m in stats["unresolved_manifests"]}
    assert "tools/requirements.txt" in unresolved  # a range, no lockfile
    assert "java/pom.xml" in unresolved
    # pinned, but nothing says the file lists the transitive tree
    assert "requirements.txt" in unresolved
    assert "web/package.json" not in unresolved  # superseded by its lockfile
    assert "web/package-lock.json" not in unresolved


@pytest.mark.parametrize(
    "text",
    [
        "requests==2.19.0\n    # via -r requirements.in\n",
        "requests==2.19.0 \\\n    --hash=sha256:abc\n",
        "# This file was autogenerated by uv via the following command:\n"
        "#    uv pip compile requirements.in\nrequests==2.19.0\n",
    ],
)
def test_a_compiled_requirements_file_covers_the_tree(tmp_path, text):
    write(tmp_path, "requirements.txt", text)
    packages, stats = osv.collect_packages(tmp_path)
    assert stats["unresolved_manifests"] == []
    assert packages[("PyPI", "requests", "2.19.0")]["version_basis"] == "locked"


def test_pinned_direct_requirements_keep_their_exact_versions(repo):
    packages, _ = osv.collect_packages(repo)
    assert packages[("PyPI", "requests", "2.19.0")]["version_basis"] == "locked"


def test_scan_reports_transitive_coverage(repo):
    class Empty(FakeClient):
        def __init__(self):
            super().__init__({})

    doc = osv.scan_api(repo, Empty())
    prov = doc["provenance"]
    assert prov["transitive_coverage"] == "partial"
    assert prov["status"] == "complete"  # lookups all answered; coverage is reported separately
    assert any(m["path"] == "java/pom.xml" for m in prov["unresolved_manifests"])


class Down(FakeClient):
    probe_failure = ("unreachable", "URLError reaching https://osv.test/v1/query")

    def query_batch(self, queries):  # pragma: no cover - must not be reached
        raise AssertionError("a failed probe must stop the scan")


def test_an_unreachable_api_fails_the_scan_fast(repo):
    doc = osv.scan_api(repo, Down({}))
    prov = doc["provenance"]
    assert prov["status"] == "failed"
    assert prov["failure"]["status"] == "unreachable"
    assert prov["packages_unanswered"] == prov["packages_queried"] > 0
    assert doc["candidates"] == []
    assert prov["transitive_coverage"] == "partial"  # coverage stats still reported


def test_scan_raises_when_the_api_is_unavailable(repo):
    with pytest.raises(RuntimeError, match=r"OSV API unavailable at https://osv\.test/v1"):
        osv.scan(repo, client=Down({}))


def test_no_package_answered_is_a_failure_not_a_degradation():
    class Nothing(FakeClient):
        def query_batch(self, queries):
            return BatchOutcome([None] * len(queries), Counter({"unreachable": len(queries)}))

    _, prov = osv.lookup(PKGS, Nothing({}))
    assert prov["status"] == "failed"


def test_some_packages_answered_is_degraded():
    class Half(FakeClient):
        def query_batch(self, queries):
            return BatchOutcome([[], None], Counter({"unreachable": 1}))

    _, prov = osv.lookup(PKGS, Half({}))
    assert prov["status"] == "degraded"
