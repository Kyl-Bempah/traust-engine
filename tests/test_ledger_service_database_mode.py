"""Database mode: the Ledger DB is the authority and the layer file is a read-only snapshot.

The mode comes from the injected context (``ledger.yaml`` → ``ctx.ledger``) and the
caller's explicit layer binding — never from environment variables.

The harness keeps working on files (LLM sessions never hold ledger credentials), but
every script write lands on the run's bound database layer and re-exports the
snapshot, so a countersign written to the database out of band (for example from
SCI) is visible to the next read. Nothing falls back to the file in this mode.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from traust_contracts.v1.models.layer import LayerActor
from traust_contracts.v1.storage import Store
from traust_ledger._internal.backends.db import DbBackend
from traust_ledger._internal.integrity.signing import SigningConfig

from traust_engine.ledger import LayerBinding, LedgerError, LedgerService

LAYER_ID = "corpus:layer:findings/org/repo/repo"
RATIONALE = "Reviewed the machine refutation and I concur; the guard is real."
AT = "2026-10-10T12:00:00+00:00"
SHELL = {
    "metadata": {
        "audit_report": "repo-security-audit.json",
        "repository": "https://example.test/org/repo",
        "created": "2026-07-01T00:00:00Z",
        "harness_version": "1.0.0",
    },
    "events": [],
    "needs_review": [],
}
HUMAN = LayerActor(kind="human", identity="alice", identity_verified=True)
MACHINE = LayerActor(kind="machine", identity="verify-remediation/test", identity_verified=True)


def _register(db: Path, repo_url: str) -> str:
    conn = sqlite3.connect(db)
    try:
        store = Store(conn)
        store.init()
        return store.register_product_repo(
            store.register_product("org"), store.register_repo(repo_url), ""
        )
    finally:
        conn.close()


@pytest.fixture
def ledger_db(tmp_path: Path) -> tuple[str, str, str]:
    """A migrated layer in a disposable SQLite Ledger: (url, owner, unrelated owner)."""
    db = tmp_path / "ledger.db"
    owner = _register(db, "https://example.test/org/repo")
    other = _register(db, "https://example.test/org/other")
    url = f"sqlite:///{db}"
    engine = create_engine(url)
    DbBackend.create_tables(engine)
    DbBackend(engine).import_layer(LAYER_ID, SHELL, product_repo_id=owner)
    return url, owner, other


def _service(url: str, binding: LayerBinding, actor: LayerActor = HUMAN) -> LedgerService:
    from traust_ledger.client import LedgerClient

    client = LedgerClient(
        backend_type="db",
        database_url=url,
        signing_config=SigningConfig(method="none"),
        signing_required=False,
    )
    client._actor = lambda: actor  # type: ignore[method-assign]  # stands in for token verification
    return LedgerService(client=client, binding=binding)


def _out_of_band_countersign(url: str, finding: str, elsewhere: Path) -> None:
    """SCI's write: straight to the database, never touching the harness's file."""
    _service(url, LayerBinding(layer_id=LAYER_ID)).countersign(
        elsewhere / "sci-side-findings-layer.json",
        finding,
        rationale=RATIONALE,
        recorded_at=AT,
        decision="false_positive",
        actor=HUMAN,
    )


def test_out_of_band_countersign_is_visible_to_the_next_read(ledger_db, tmp_path) -> None:
    url, owner, _ = ledger_db
    snapshot = tmp_path / "work" / "repo-findings-layer.json"
    svc = _service(url, LayerBinding(product_repo_id=owner))

    assert svc.database_mode
    assert svc.layer_id_for(snapshot) == LAYER_ID  # bound by owner, not by the path
    assert svc.read_layer_file(snapshot)["events"] == []

    _out_of_band_countersign(url, "FIND-001", tmp_path / "sci")

    layer = svc.read_layer_file(snapshot)
    assert [e["finding_ref"] for e in layer["events"]] == ["FIND-001"]
    on_disk = json.loads(snapshot.read_text(encoding="utf-8"))
    assert on_disk == layer  # the file the LLM reads is the refreshed snapshot
    assert on_disk["metadata"]["merkle_size"] == 1
    assert not snapshot.stat().st_mode & 0o222  # read-only for sessions


def test_script_writes_land_in_the_database_and_refresh_the_snapshot(ledger_db, tmp_path) -> None:
    url, owner, _ = ledger_db
    snapshot = tmp_path / "repo-findings-layer.json"
    _out_of_band_countersign(url, "FIND-001", tmp_path / "sci")

    svc = _service(url, LayerBinding(layer_id=LAYER_ID, product_repo_id=owner), actor=MACHINE)
    svc.submit_events(
        snapshot,
        [
            {
                "finding_ref": "FIND-002",
                "disposition": {"resolution": "open"},
                "rationale": RATIONALE,
                "recorded_at": AT,
                "source": {"type": "verification_report", "ref": "repo-verification.json"},
            }
        ],
    )

    stored = DbBackend(create_engine(url)).load_layer_id(LAYER_ID)
    assert [e["finding_ref"] for e in stored["events"]] == ["FIND-001", "FIND-002"]
    assert json.loads(snapshot.read_text(encoding="utf-8")) == stored


def test_binding_must_match_its_owner(ledger_db, tmp_path) -> None:
    url, _, other = ledger_db
    path = tmp_path / "repo-findings-layer.json"
    with pytest.raises(LedgerError, match="has no ledger layer"):
        _service(url, LayerBinding(product_repo_id=other)).read_layer_file(path)
    with pytest.raises(LedgerError, match="needs a layer_id or a product_repo_id"):
        LayerBinding()
    assert not path.exists()


def test_database_mode_never_creates_or_falls_back_to_the_file(ledger_db, tmp_path) -> None:
    url, _, _ = ledger_db
    path = tmp_path / "absent-findings-layer.json"
    path.write_text(json.dumps(SHELL), encoding="utf-8")  # a stale file must not be used
    with pytest.raises(LedgerError, match="not found"):
        _service(url, LayerBinding(layer_id="corpus:layer:absent")).ensure_layer_file(
            path, shell=SHELL
        )
    assert DbBackend(create_engine(url)).list_layer_ids() == [LAYER_ID]


def _ops(ledger_dsn: str | None):
    """LedgerOps on the suite's config, with or without a ``ledger.yaml`` section."""
    from traust_contracts import load_context
    from traust_contracts.config import LedgerConfig

    from traust_engine.ledger.ops import LedgerOps

    ledger = LedgerConfig(dsn=ledger_dsn) if ledger_dsn else None
    return LedgerOps(load_context().model_copy(update={"ledger": ledger}))


def test_ledger_config_selects_database_mode_for_the_given_layer(ledger_db, tmp_path) -> None:
    url, owner, _ = ledger_db
    ops = _ops(url)
    assert ops.database_configured
    svc = ops.service(tmp_path, layer=LayerBinding(product_repo_id=owner))
    assert svc.database_mode
    assert svc.layer_id_for(tmp_path / "repo-findings-layer.json") == LAYER_ID


def test_ledger_config_requires_an_explicit_binding(ledger_db, tmp_path) -> None:
    url, _, _ = ledger_db
    with pytest.raises(LedgerError, match="pass the run's layer binding"):
        _ops(url).service(tmp_path)


def test_binding_without_ledger_config_refuses(tmp_path) -> None:
    ops = _ops(None)
    assert not ops.database_configured
    with pytest.raises(LedgerError, match=r"ledger\.yaml sets no dsn"):
        ops.service(tmp_path, layer=LayerBinding(layer_id=LAYER_ID))
    with pytest.raises(LedgerError, match="needs a database client"):
        LedgerService(data_dir=tmp_path, binding=LayerBinding(layer_id=LAYER_ID))


def test_pull_exports_the_bound_layer(ledger_db, tmp_path) -> None:
    url, owner, _ = ledger_db
    snapshot = tmp_path / "repo-findings-layer.json"
    layer = _ops(url).pull(snapshot, LayerBinding(product_repo_id=owner))
    assert json.loads(snapshot.read_text(encoding="utf-8")) == layer


def test_ledger_config_without_dsn_stays_file_mode(tmp_path) -> None:
    """signing/identity alone (no dsn) keep layer files as the ledger."""
    from traust_contracts import load_context
    from traust_contracts.config import LedgerConfig, LedgerSigning

    from traust_engine.ledger.ops import LedgerOps

    ledger = LedgerConfig(signing=LedgerSigning(method="keypair"))
    ops = LedgerOps(load_context().model_copy(update={"ledger": ledger}))
    assert not ops.database_configured
    assert not ops.service(tmp_path).database_mode


def test_environment_never_switches_modes(ledger_db, monkeypatch, tmp_path) -> None:
    """The Ledger SDK's LAAS_* variables must not change what the engine does."""
    url, _, _ = ledger_db
    monkeypatch.setenv("LAAS_BACKEND_TYPE", "db")
    monkeypatch.setenv("LAAS_DATABASE_URL", url)
    assert not LedgerService(data_dir=tmp_path).database_mode
    assert not _ops(None).service(tmp_path).database_mode


def test_bare_postgresql_dsn_uses_psycopg() -> None:
    from traust_engine.ledger.service import ledger_database_url

    assert ledger_database_url("postgresql://u@h/db") == "postgresql+psycopg://u@h/db"
    assert ledger_database_url("postgresql+psycopg://u@h/db") == "postgresql+psycopg://u@h/db"
    assert ledger_database_url("sqlite:////tmp/l.db") == "sqlite:////tmp/l.db"


def test_file_mode_is_unchanged(tmp_path) -> None:
    path = tmp_path / "repo-findings-layer.json"
    path.write_text(json.dumps(SHELL), encoding="utf-8")
    svc = LedgerService(data_dir=tmp_path)
    assert not svc.database_mode
    assert svc.layer_id_for(path) == "repo-findings-layer"
    assert svc.read_layer_file(path) == SHELL
    with pytest.raises(LedgerError, match="needs database mode"):
        svc.write_snapshot(path)


# ─── Mismatch and divergence guards ──────────────────────────────────────────


def test_one_service_binds_one_layer_path(ledger_db, tmp_path) -> None:
    """A second path must not silently read or write the bound layer under another name."""
    url, owner, _ = ledger_db
    svc = _service(url, LayerBinding(product_repo_id=owner))
    svc.read_layer_file(tmp_path / "repo" / "repo-findings-layer.json")
    with pytest.raises(LedgerError, match="binds one layer per run"):
        svc.read_layer_file(tmp_path / "other" / "other-findings-layer.json")
    with pytest.raises(LedgerError, match="binds one layer per run"):
        svc.countersign(
            tmp_path / "other" / "other-findings-layer.json",
            "FIND-009",
            rationale=RATIONALE,
            recorded_at=AT,
            decision="false_positive",
            actor=HUMAN,
        )
    events = DbBackend(create_engine(url)).load_layer_id(LAYER_ID)["events"]
    assert events == []


def test_file_mode_refuses_to_write_over_a_snapshot(ledger_db, tmp_path) -> None:
    """A process without ledger.yaml must not fork the ledger on disk."""
    from traust_engine.ledger.service import snapshot_marker

    url, owner, _ = ledger_db
    snapshot = tmp_path / "repo-findings-layer.json"
    _service(url, LayerBinding(product_repo_id=owner)).read_layer_file(snapshot)
    assert snapshot_marker(snapshot).is_file()

    file_svc = LedgerService(data_dir=tmp_path)
    assert file_svc.read_layer_file(snapshot)["events"] == []  # reading is allowed
    for write in (
        lambda: file_svc.ensure_layer_file(snapshot, shell=SHELL),
        lambda: file_svc.sign(snapshot),
        lambda: file_svc.patch_layer_file(snapshot, {"claim_hashes": {}}),
        lambda: file_svc.submit_events(snapshot, []),
    ):
        with pytest.raises(LedgerError, match="read-only database snapshot"):
            write()


def test_unchanged_snapshot_is_not_rewritten(ledger_db, tmp_path) -> None:
    """Reads must not bump mtime when nothing changed (drift checks, git status)."""
    import os

    url, owner, _ = ledger_db
    snapshot = tmp_path / "repo-findings-layer.json"
    svc = _service(url, LayerBinding(product_repo_id=owner))
    svc.read_layer_file(snapshot)
    os.utime(snapshot, (1_000_000_000, 1_000_000_000))
    svc.read_layer_file(snapshot)
    assert snapshot.stat().st_mtime == 1_000_000_000

    _out_of_band_countersign(url, "FIND-001", tmp_path / "sci")
    svc.read_layer_file(snapshot)
    assert snapshot.stat().st_mtime != 1_000_000_000


def test_committed_write_survives_a_failed_snapshot_refresh(
    ledger_db, tmp_path, monkeypatch
) -> None:
    """The database write is durable; a failed export removes the stale file, no raise."""
    from traust_engine.ledger import service as service_mod

    url, owner, _ = ledger_db
    snapshot = tmp_path / "repo-findings-layer.json"
    svc = _service(url, LayerBinding(product_repo_id=owner))
    svc.read_layer_file(snapshot)

    def fail(*_a, **_k):
        raise OSError("disk full")

    monkeypatch.setattr(service_mod, "_write_atomic", fail)
    svc.countersign(
        snapshot,
        "FIND-002",
        rationale=RATIONALE,
        recorded_at=AT,
        decision="false_positive",
        actor=HUMAN,
    )
    events = DbBackend(create_engine(url)).load_layer_id(LAYER_ID)["events"]
    assert [e["finding_ref"] for e in events] == ["FIND-002"]
    assert not snapshot.exists()
    assert not service_mod.snapshot_marker(snapshot).exists()


def test_missing_layer_explains_who_creates_it(ledger_db, tmp_path) -> None:
    url, _, _ = ledger_db
    with pytest.raises(LedgerError, match="never creates layers"):
        _service(url, LayerBinding(layer_id="corpus:layer:absent")).read_layer_file(
            tmp_path / "absent-findings-layer.json"
        )


def test_binding_and_snapshot_are_logged(ledger_db, tmp_path, caplog) -> None:
    url, owner, _ = ledger_db
    caplog.set_level("INFO", logger="traust_engine.ledger.service")
    _service(url, LayerBinding(product_repo_id=owner)).read_layer_file(
        tmp_path / "repo-findings-layer.json"
    )
    messages = [r.getMessage() for r in caplog.records]
    assert any("bound layer_id=" + LAYER_ID in m for m in messages)
    assert any("snapshot exported" in m and "merkle_size=" in m for m in messages)
    assert not any(url in m for m in messages)  # the DSN is never logged


# ─── signing and identity from ledger.yaml ───────────────────────────────────


def test_without_ledger_yaml_the_environment_is_ignored(monkeypatch, tmp_path) -> None:
    """No ledger.yaml means explicit defaults, not the Ledger SDK's env fallbacks."""
    from traust_engine.ledger import ClientSettings

    monkeypatch.setenv("LAAS_SIGNING_REQUIRED", "1")
    monkeypatch.setenv("LAAS_SIGNING_KEY_PATH", "/env/other.key")
    monkeypatch.setenv("LEDGER_DIRECTORY_COMMAND", "/nonexistent/directory")
    settings = ClientSettings.from_config(None)
    assert settings.signing_required is False
    assert settings.signing_config.key_path is None
    assert settings.directory is False
    assert settings.verifier is None and not settings.database
    client = LedgerService(data_dir=tmp_path, settings=settings)._client
    assert client._config.signing_required is False


def test_signing_config_comes_from_ledger_yaml_not_env(monkeypatch, tmp_path) -> None:
    from traust_contracts.config import LedgerConfig, LedgerSigning

    from traust_engine.ledger import ClientSettings

    monkeypatch.setenv("LAAS_SIGNING_METHOD", "identity")
    monkeypatch.setenv("LAAS_SIGNING_KEY_PATH", "/env/other.key")
    monkeypatch.setenv("LAAS_SIGNING_REQUIRED", "0")
    ledger = LedgerConfig(
        signing=LedgerSigning(required=True, method="keypair", key_path="/run/cosign.key")
    )
    settings = ClientSettings.from_config(ledger)
    signing = settings.signing_config
    assert (signing.method, signing.key_path) == ("keypair", "/run/cosign.key")
    assert signing.oidc_token is None  # never read from the environment
    assert settings.signing_required is True
    client = LedgerService(data_dir=tmp_path, settings=settings)._client
    assert client._config.signing_required is True


def test_identity_config_builds_verifier_and_directory() -> None:
    from traust_contracts.config import LedgerConfig, LedgerIdentity
    from traust_ledger.auth.directory import DirectoryUnavailableError, ScriptDirectory
    from traust_ledger.auth.verifier import TokenVerifier

    from traust_engine.ledger import ClientSettings

    settings = ClientSettings.from_config(
        LedgerConfig(
            identity=LedgerIdentity(
                oidc_issuer="https://issuer.example",
                oidc_audience="laas-api",
                jwks_url="https://issuer.example/keys",
                directory_command="/bin/echo active",
            )
        )
    )
    assert isinstance(settings.verifier, TokenVerifier)
    assert settings.verifier._config.audience == "laas-api"
    assert isinstance(settings.directory, ScriptDirectory)

    with pytest.raises(DirectoryUnavailableError):  # fail closed on a missing program
        ClientSettings.from_config(
            LedgerConfig(identity=LedgerIdentity(directory_command="/nonexistent/directory"))
        )


def test_database_mode_uses_the_same_settings(ledger_db) -> None:
    from traust_contracts.config import LedgerConfig, LedgerSigning

    from traust_engine.ledger import ClientSettings

    url, owner, _ = ledger_db
    settings = ClientSettings.from_config(
        LedgerConfig(dsn=url, signing=LedgerSigning(method="keypair"))
    )
    svc = LedgerService.database(settings, LayerBinding(product_repo_id=owner))
    assert svc.database_mode
    assert svc._client._config.signing_required is False
    with pytest.raises(LedgerError, match=r"use LedgerService\.database"):
        LedgerService(data_dir=Path("/tmp"), settings=settings)


def test_settings_are_resolved_once_per_context(ledger_db) -> None:
    url, _, _ = ledger_db
    ops = _ops(url)
    assert ops.settings is ops.settings


def test_run_binding_applies_to_later_service_calls(ledger_db, tmp_path) -> None:
    url, owner, other = ledger_db
    ops = _ops(url)
    ops.bind(LayerBinding(product_repo_id=owner))
    assert ops.service(tmp_path).layer_id_for(tmp_path / "repo-findings-layer.json") == LAYER_ID
    assert ops.pull(tmp_path / "repo-findings-layer.json")["events"] == []
    ops.bind(LayerBinding(product_repo_id=owner))  # same binding again is fine
    with pytest.raises(LedgerError, match="run already bound"):
        ops.bind(LayerBinding(product_repo_id=other))
