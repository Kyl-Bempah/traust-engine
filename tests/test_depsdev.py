"""deps.dev resolution: the client's failure rule, the cache, and the pre-scan wiring."""

import io
import json
import urllib.error
from collections import Counter
from pathlib import Path

from traust_engine.adapters import osv
from traust_engine.depsdev import ATTRIBUTION, DepsDevClient, Resolution, normalize_base_url
from traust_engine.osv import BatchOutcome

GRAPH = {
    "nodes": [
        {
            "versionKey": {"system": "PYPI", "name": "requests", "version": "2.19.0"},
            "relation": "SELF",
        },
        {
            "versionKey": {"system": "PYPI", "name": "urllib3", "version": "1.23"},
            "relation": "DIRECT",
        },
        {
            "versionKey": {"system": "PYPI", "name": "idna", "version": "2.7"},
            "relation": "INDIRECT",
        },
    ]
}


class Opener:
    def __init__(self, reply):
        self.reply, self.urls = reply, []

    def __call__(self, req, timeout=None):
        self.urls.append(req.full_url)
        r = self.reply(req.full_url) if callable(self.reply) else self.reply
        if isinstance(r, Exception):
            raise r
        if isinstance(r, int):
            raise urllib.error.HTTPError(req.full_url, r, "err", {}, None)
        return io.BytesIO(json.dumps(r).encode())


def client(reply, **kw):
    op = Opener(reply)
    return DepsDevClient("https://dd.test/v3", opener=op, sleep=lambda s: None, **kw), op


def test_normalize_base_url_accepts_a_template():
    assert (
        normalize_base_url("https://api.deps.dev/v3/systems/{ident}") == "https://api.deps.dev/v3"
    )
    assert normalize_base_url(None) == "https://api.deps.dev/v3"


def test_url_quotes_scoped_and_maven_names():
    c, _ = client(GRAPH)
    assert c.url("npm", "@babel/core", "7.22.0").endswith(
        "/systems/npm/packages/%40babel%2Fcore/versions/7.22.0:dependencies"
    )
    assert "/packages/org.yaml%3Asnakeyaml/" in c.url("Maven", "org.yaml:snakeyaml", "1.33")


def test_graph_excludes_self():
    c, _ = client(GRAPH)
    res = c.dependencies("PyPI", "requests", "2.19.0")
    assert res.ok
    assert res.nodes == [("idna", "2.7", "INDIRECT"), ("urllib3", "1.23", "DIRECT")]


def test_failures_are_never_an_empty_graph():
    for reply, status in [
        (404, "not-found"),
        (429, "quota-deferred"),
        (503, "unreachable"),
        (urllib.error.URLError("down"), "unreachable"),
        (400, "error"),
    ]:
        c, _ = client(reply)
        res = c.dependencies("PyPI", "requests", "2.19.0")
        assert res.status == status and res.nodes == []
    c, _ = client(GRAPH)
    assert c.dependencies("RubyGems", "rails", "7.0.0").status == "unsupported"


def test_probe_treats_not_found_as_an_answer():
    assert client(404)[0].probe(("PyPI", "nope", "0")) is None
    assert client(503)[0].probe(("PyPI", "requests", "1"))[0] == "unreachable"


def test_cache_serves_answers_and_never_stores_failures(tmp_path):
    now = [1000.0]
    c, op = client(GRAPH, cache_dir=tmp_path, clock=lambda: now[0])
    c.dependencies("PyPI", "requests", "2.19.0")
    again = c.dependencies("PyPI", "requests", "2.19.0")
    assert again.cached and len(op.urls) == 1
    now[0] += 25 * 3600  # past the 24 h TTL
    assert not c.dependencies("PyPI", "requests", "2.19.0").cached
    bad, op2 = client(503, cache_dir=tmp_path / "f", retries=1)
    bad.dependencies("PyPI", "x", "1")
    bad.dependencies("PyPI", "x", "1")
    assert len(op2.urls) == 2


# -- the pre-scan wiring ---------------------------------------------------------


class FakeResolver:
    base_url = "https://dd.test/v3"

    def __init__(self, answers, failure=None, defaults=None):
        self.answers, self.failure, self.asked = answers, failure, []
        self.defaults = defaults or {}

    def defaults_many(self, names):
        return {
            n: Resolution("ok", [(n[1], self.defaults[n], "DEFAULT")])
            if n in self.defaults
            else Resolution("not-found")
            for n in names
        }

    def probe(self, key):
        return self.failure

    def resolve_many(self, keys):
        keys = list(keys)
        self.asked += keys
        out = {k: self.answers.get(k, Resolution("not-found")) for k in keys}
        return out, Counter(r.status for r in out.values())


class FakeOsv:
    base_url = "https://osv.test/v1"

    def probe(self, query):
        return None

    def query_batch(self, queries):
        return BatchOutcome([[] for _ in queries], Counter())

    def get_vulns(self, ids):
        return {}, Counter()


def write(root: Path, rel: str, text: str):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def repo(tmp_path):
    write(tmp_path, "requirements.txt", "requests==2.19.0\n")
    write(tmp_path, "tools/requirements.txt", "flask>=1.0\nunversioned\n")
    return tmp_path


REQ = ("PyPI", "requests", "2.19.0")


def test_resolution_adds_the_tree_and_resolves_the_manifest(tmp_path):
    packages, stats = osv.collect_packages(repo(tmp_path))
    answers = {REQ: Resolution("ok", [("idna", "2.7", "INDIRECT"), ("urllib3", "1.23", "DIRECT")])}
    block = osv.resolve_transitive(packages, stats, FakeResolver(answers))
    added = packages[("PyPI", "urllib3", "1.23")]
    assert added["version_basis"] == "resolved"
    assert added["resolved_via"] == ["requests@2.19.0"]
    assert added["sources"] == ["requirements.txt"]
    assert [m["path"] for m in stats["resolved_manifests"]] == ["requirements.txt"]
    (still,) = stats["unresolved_manifests"]  # flask not found; "unversioned" has no default
    assert still["path"] == "tools/requirements.txt"
    assert still["reason"] == {
        "no version, deps.dev default not-found": 1,
        "deps.dev not-found": 1,
    }
    assert block["status"] == "complete"
    assert block["license"] == "CC-BY-4.0" and block["attribution"] == ATTRIBUTION
    assert block["packages_added"] == 2


def test_a_declared_version_outranks_a_resolved_one(tmp_path):
    write(tmp_path, "requirements.txt", "requests==2.19.0\nurllib3==1.23\n")
    packages, stats = osv.collect_packages(tmp_path)
    answers = {REQ: Resolution("ok", [("urllib3", "1.23", "DIRECT")])}
    osv.resolve_transitive(packages, stats, FakeResolver(answers))
    assert packages[("PyPI", "urllib3", "1.23")]["version_basis"] == "locked"
    assert "resolved_via" not in packages[("PyPI", "urllib3", "1.23")]


def test_an_unreachable_resolver_leaves_everything_unresolved(tmp_path):
    packages, stats = osv.collect_packages(repo(tmp_path))
    before = set(packages)
    block = osv.resolve_transitive(
        packages, stats, FakeResolver({}, failure=("unreachable", "down"))
    )
    assert set(packages) == before
    assert block["status"] == "failed" and block["failure"]["status"] == "unreachable"
    assert {m["path"] for m in stats["unresolved_manifests"]} == {
        "requirements.txt",
        "tools/requirements.txt",
    }
    assert stats["unresolved_manifests"][0]["reason"]


def test_scan_api_reports_resolution_and_coverage(tmp_path):
    answers = {
        REQ: Resolution("ok", [("urllib3", "1.23", "DIRECT")]),
        ("PyPI", "flask", "1.0"): Resolution("ok", [("click", "8.0", "DIRECT")]),
    }
    write(tmp_path, "requirements.txt", "requests==2.19.0\nflask>=1.0\n")
    doc = osv.scan_api(tmp_path, FakeOsv(), resolver=FakeResolver(answers))
    prov = doc["provenance"]
    assert prov["transitive_coverage"] == "complete"
    assert prov["resolution"]["manifests_resolved"] == 1
    assert prov["packages_queried"] == 4


def test_go_and_lockfiles_are_never_sent(tmp_path):
    write(tmp_path, "go.mod", "module x\n\ngo 1.21\n\nrequire golang.org/x/net v0.17.0\n")
    write(tmp_path, "web/package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {}}))
    packages, stats = osv.collect_packages(tmp_path)
    r = FakeResolver({})
    block = osv.resolve_transitive(packages, stats, r)
    assert r.asked == [] and block["direct_dependencies"] == 0


def test_a_declaration_without_a_version_resolves_at_the_default(tmp_path):
    write(tmp_path, "requirements.txt", "httpx\n")
    packages, stats = osv.collect_packages(tmp_path)
    answers = {("PyPI", "httpx", "0.28.1"): Resolution("ok", [("h11", "0.16.0", "INDIRECT")])}
    r = FakeResolver(answers, defaults={("PyPI", "httpx"): "0.28.1"})
    block = osv.resolve_transitive(packages, stats, r)
    assert packages[("PyPI", "httpx", "0.28.1")]["version_basis"] == "resolved-default"
    assert packages[("PyPI", "h11", "0.16.0")]["resolved_via"] == ["httpx@0.28.1"]
    assert stats["unresolved_manifests"] == []
    assert block["defaulted"] == 1


def test_a_declared_name_overrides_resolved_versions_for_pypi_and_maven(tmp_path):
    write(tmp_path, "requirements.txt", "requests==2.19.0\nurllib3==1.20\n")
    write(tmp_path, "web/package.json", '{"dependencies": {"a": "1.0.0", "b": "2.0.0"}}')
    packages, stats = osv.collect_packages(tmp_path)
    answers = {
        REQ: Resolution("ok", [("urllib3", "1.23", "DIRECT")]),
        ("npm", "a", "1.0.0"): Resolution("ok", [("b", "1.5.0", "DIRECT")]),
    }
    block = osv.resolve_transitive(packages, stats, FakeResolver(answers))
    assert ("PyPI", "urllib3", "1.23") not in packages  # pip installs the declared 1.20
    assert ("npm", "b", "1.5.0") in packages  # npm can nest a second version
    assert block["overridden_by_declaration"] == 1


def test_default_version_reads_is_default():
    pkg = {
        "versions": [
            {"versionKey": {"name": "httpx", "version": "0.27.0"}},
            {"versionKey": {"name": "httpx", "version": "0.28.1"}, "isDefault": True},
        ]
    }
    c, op = client(pkg)
    res = c.default_version("PyPI", "httpx")
    assert res.nodes == [("httpx", "0.28.1", "DEFAULT")]
    assert op.urls == ["https://dd.test/v3/systems/pypi/packages/httpx"]
    assert client({"versions": []})[0].default_version("PyPI", "x").status == "not-found"


def test_the_pypi_override_is_per_requirements_file(tmp_path):
    write(tmp_path, "requirements.txt", "requests==2.19.0\nurllib3==1.20\n")
    write(tmp_path, "docs/requirements.txt", "requests==2.19.0\n")
    packages, stats = osv.collect_packages(tmp_path)
    answers = {REQ: Resolution("ok", [("urllib3", "1.23", "DIRECT")])}
    osv.resolve_transitive(packages, stats, FakeResolver(answers))
    # docs/ is its own environment: it gets the resolved urllib3
    assert packages[("PyPI", "urllib3", "1.23")]["sources"] == ["docs/requirements.txt"]


def test_the_maven_override_is_repo_wide(tmp_path):
    pom = "<project><dependencies>{}</dependencies></project>"
    dep = "<dependency><groupId>{}</groupId><artifactId>{}</artifactId><version>{}</version></dependency>"
    write(tmp_path, "pom.xml", pom.format(dep.format("org.yaml", "snakeyaml", "2.0")))
    write(tmp_path, "mod/pom.xml", pom.format(dep.format("org.example", "lib", "1.0")))
    packages, stats = osv.collect_packages(tmp_path)
    answers = {
        ("Maven", "org.example:lib", "1.0"): Resolution(
            "ok", [("org.yaml:snakeyaml", "2.2", "DIRECT")]
        )
    }
    block = osv.resolve_transitive(packages, stats, FakeResolver(answers))
    assert ("Maven", "org.yaml:snakeyaml", "2.2") not in packages
    assert block["overridden_by_declaration"] == 1


# -- test / dev scope tagging (owner decision 2026-10-21: tag, never skip) ------


def test_declared_scopes():
    pkg = '{"dependencies": {"a": "1"}, "devDependencies": {"jest": "29.0.0", "a": "1"}}'
    assert osv.declared_scopes("package.json", pkg) == {"jest": "dev"}
    pom = (
        "<project><dependencies>"
        "<dependency><groupId>junit</groupId><artifactId>junit</artifactId>"
        "<version>4.12</version><scope>test</scope></dependency>"
        "<dependency><groupId>org.x</groupId><artifactId>core</artifactId>"
        "<version>1</version></dependency>"
        "</dependencies></project>"
    )
    assert osv.declared_scopes("pom.xml", pom) == {"junit:junit": "test"}
    cargo = '[dependencies]\nserde = "1"\n[dev-dependencies]\nproptest = "1"\n'
    assert osv.declared_scopes("Cargo.toml", cargo) == {"proptest": "dev"}
    poetry = (
        '[tool.poetry.dependencies]\nrequests = "2"\n'
        '[tool.poetry.group.test.dependencies]\nPy_Test = "7"\n'
    )
    assert osv.declared_scopes("pyproject.toml", poetry) == {"py-test": "dev"}
    assert osv.declared_scopes("package.json", "not json") == {}


def _pom(tmp_path, deps):
    dep = (
        "<dependency><groupId>{}</groupId><artifactId>{}</artifactId>"
        "<version>{}</version>{}</dependency>"
    )
    body = "".join(dep.format(g, a, v, f"<scope>{s}</scope>" if s else "") for g, a, v, s in deps)
    write(tmp_path, "pom.xml", f"<project><dependencies>{body}</dependencies></project>")


def test_a_test_scoped_tree_is_tagged_test(tmp_path):
    _pom(tmp_path, [("org.apache.jmeter", "ApacheJMeter_java", "2.10", "test")])
    packages, stats = osv.collect_packages(tmp_path)
    key = ("Maven", "org.apache.jmeter:ApacheJMeter_java", "2.10")
    answers = {key: Resolution("ok", [("org.bouncycastle:bcprov-jdk15on", "1.49", "INDIRECT")])}
    osv.resolve_transitive(packages, stats, FakeResolver(answers))
    assert (
        osv._scope_tag(packages[("Maven", "org.bouncycastle:bcprov-jdk15on", "1.49")]["scopes"])
        == "test"
    )
    assert osv._scope_tag(packages[key]["scopes"]) == "test"


def test_a_runtime_path_removes_the_tag(tmp_path):
    _pom(tmp_path, [("org.x", "testlib", "1.0", "test"), ("org.x", "app", "1.0", None)])
    packages, stats = osv.collect_packages(tmp_path)
    shared = ("org.x:shared", "2.0", "DIRECT")
    answers = {
        ("Maven", "org.x:testlib", "1.0"): Resolution("ok", [shared]),
        ("Maven", "org.x:app", "1.0"): Resolution("ok", [shared]),
    }
    osv.resolve_transitive(packages, stats, FakeResolver(answers))
    assert osv._scope_tag(packages[("Maven", "org.x:shared", "2.0")]["scopes"]) is None


def test_candidates_carry_dependency_scope(tmp_path):
    write(tmp_path, "web/package.json", '{"devDependencies": {"jest": "29.0.0"}}')

    class OneHit(FakeOsv):
        def query_batch(self, queries):
            return BatchOutcome(
                [["GHSA-j"] if q.name == "jest" else [] for q in queries], Counter()
            )

        def get_vulns(self, ids):
            return {"GHSA-j": {"id": "GHSA-j"}}, Counter()

    doc = osv.scan_api(tmp_path, OneHit())
    (c,) = doc["candidates"]
    assert c["dependency_scope"] == "dev"
    json.dumps(doc)  # nothing unserialisable (the internal scope sets) leaks out
