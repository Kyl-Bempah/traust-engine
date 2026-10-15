"""The bundled rule packs are the single, default copy — and a default run uses them.

traust-engine ships the opengrep rule pack and the gitleaks config inside the
package. No consumer configures them: with no rule-pack argument and no
``locations`` override, the adapters resolve to these copies. These tests
pin that contract end to end, so a default run that stops loading current
rules fails instead of silently scanning with stale ones. They are not
marked ``integration``, so the pre-push hook runs them wherever opengrep and
gitleaks are installed (and skips them cleanly where they are not).
"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from traust_engine.adapters import gitleaks as G
from traust_engine.adapters import opengrep as O
from traust_engine.assets import default_gitleaks_config, default_rule_pack_dir

PACK = default_rule_pack_dir()
LANG_DIRS = sorted(p for p in PACK.iterdir() if p.is_dir())

# One snippet per canary rule. Each canary is a recent addition, so a pack
# that falls behind (or a default that resolves elsewhere) loses it first.
CANARIES = {
    "app.py": (
        "import jwt\n\n\n"
        "def read(token):\n"
        '    return jwt.decode(token, options={"verify_signature": False})\n',
        "traust-python-authentication-jwt-signature-unverified",
    ),
    "owners.go": (
        "package owners\n\n"
        'import "database/sql"\n\n'
        "func robots(db *sql.DB, owner string) {\n"
        '\tdb.Query("SELECT name FROM users WHERE name LIKE \'" + owner + "+%\'")\n'
        "}\n",
        "traust-go-injection-like-wildcard-unescaped",
    ),
}


class TestDefaultResolution(unittest.TestCase):
    def test_no_argument_no_config_resolves_to_the_bundled_pack(self):
        self.assertEqual(O.resolve_rule_pack_dir(None, None), PACK)

    def test_no_argument_no_config_resolves_to_the_bundled_gitleaks_config(self):
        self.assertEqual(G.resolve_gitleaks_config(None, None), default_gitleaks_config())

    def test_every_rule_file_has_a_fixture(self):
        missing = []
        for rules in PACK.glob("*/*.yaml"):
            if rules.name.endswith(".test.yaml"):
                continue
            stem = rules.name[: -len(".yaml")]
            if not any(
                p != rules and p.name.startswith(stem + ".") for p in rules.parent.iterdir()
            ):
                missing.append(str(rules.relative_to(PACK)))
        self.assertEqual(missing, [], "rule files with no same-basename fixture")


@unittest.skipUnless(shutil.which("opengrep"), "opengrep not on PATH")
class TestBundledOpengrepPack(unittest.TestCase):
    def test_every_language_passes_its_fixtures(self):
        self.assertTrue(LANG_DIRS)
        for lang in LANG_DIRS:
            proc = subprocess.run(
                ["opengrep", "test", str(lang)], capture_output=True, text=True, check=False
            )
            self.assertIn("All tests passed", proc.stdout + proc.stderr, lang.name)

    def test_default_scan_reports_the_canary_rules(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for name, (code, _rule) in CANARIES.items():
                (root / name).write_text(code, encoding="utf-8")
            result = O.scan(root)  # no rules, no rule_pack, no loc: the default path
        found = {f.id if hasattr(f, "id") else f["id"] for f in result.findings}
        for _name, (_code, rule) in CANARIES.items():
            self.assertIn(f"opengrep/{rule}", found)


@unittest.skipUnless(shutil.which("gitleaks"), "gitleaks not on PATH")
class TestBundledGitleaksConfig(unittest.TestCase):
    def test_default_scan_reports_a_traust_detector(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "settings.py").write_text(
                'TOKEN = "sha256~' + "B" * 43 + '"\n', encoding="utf-8"
            )
            result = G.scan(root)  # no config, no loc: the bundled default
        found = {f.id if hasattr(f, "id") else f["id"] for f in result.findings}
        self.assertIn("gitleaks/traust-openshift-sha256-token", found)


class TestNosemComments(unittest.TestCase):
    """A target's own nosem comments never suppress a fact (they flag it)."""

    def test_normalize_flags_a_nosem_comment_on_the_match(self):
        raw = {
            "results": [
                {
                    "check_id": "x.traust-demo",
                    "path": "app.py",
                    "start": {"line": 1},
                    "end": {"line": 1},
                    "extra": {"lines": "danger()  # nosemgrep", "message": "m"},
                }
            ]
        }
        facts, _ = O.normalize(raw, Path("/nonexistent"))
        self.assertTrue(facts[0]["nosem_marked"])
        self.assertIn("nosem", O._facts_to_findings(facts)[0]["description"])

    def test_normalize_reads_a_nosem_comment_on_the_line_above(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "app.go").write_text("// nosem: traust-demo\ndanger()\n", encoding="utf-8")
            raw = {
                "results": [
                    {
                        "check_id": "traust-demo",
                        "path": str(root / "app.go"),
                        "start": {"line": 2},
                        "end": {"line": 2},
                        "extra": {"lines": "danger()", "message": "m"},
                    }
                ]
            }
            facts, _ = O.normalize(raw, root)
        self.assertTrue(facts[0]["nosem_marked"])

    def test_unmarked_fact_is_not_flagged(self):
        raw = {"results": [{"check_id": "r", "path": "a.py", "extra": {"lines": "x()"}}]}
        facts, _ = O.normalize(raw, Path("/nonexistent"))
        self.assertFalse(facts[0]["nosem_marked"])

    @unittest.skipUnless(shutil.which("opengrep"), "opengrep not on PATH")
    def test_default_scan_reports_a_fact_the_target_marked_nosem(self):
        code, rule = CANARIES["app.py"]
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            marked = code.replace("False})\n", "False})  # nosemgrep\n")
            (root / "app.py").write_text(marked, encoding="utf-8")
            result = O.scan(root)
        found = {f.id if hasattr(f, "id") else f["id"] for f in result.findings}
        self.assertIn(f"opengrep/{rule}", found)
