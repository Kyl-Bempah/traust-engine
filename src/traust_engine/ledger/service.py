"""LedgerService — the traust-engine's gateway to traust-ledger.

Wraps ``LedgerClient`` (the in-process Python SDK) so the harness has a
single object for all ledger I/O.  Callers interact with the ledger through
this service, never through scattered imports of traust-ledger internals.

All write operations delegate to ``LedgerClient`` → ``Backend``.
Backend-agnostic; work with file or db materializers.  Every write
is atomic (mutate + stamp + sign inside one lock).

Pure computation (fingerprint, compute_event_id, derive_disposition) stays
importable directly from traust_engine.ledger — those are stateless
algorithms that don't need a service boundary.

Everything comes from the injected context (``HarnessContext.ledger``, i.e.
``ledger.yaml``) through :class:`ClientSettings`, never from environment
variables: every ``LedgerClient`` argument is passed explicitly, so the Ledger
SDK's ``LAAS_*`` / ``LEDGER_*`` fallbacks never apply. The one exception is the
caller's token (``ledger auth login``, a token file or ``LAAS_TOKEN``) — a
credential of the caller, not deployment config.

* **File mode** (no ``dsn``): the layer file beside the audit *is* the ledger,
  addressed by its filename stem.
* **Database mode** (``dsn`` set): the Ledger database is the authority. The
  service is bound to one layer (a :class:`LayerBinding` the caller passes),
  every read and write goes to that layer, and the layer file is a read-only
  *snapshot* re-exported after each read or write. Nothing falls back to the file.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from traust_contracts.config import LedgerConfig, LedgerIdentity, LedgerSigning
from traust_contracts.v1.models.layer import LayerActor
from traust_ledger.api import reports
from traust_ledger.auth.directory import (
    DIRECTORY_COMMAND_ENV,
    EmployeeDirectory,
    load_directory,
)
from traust_ledger.auth.discovery import discover_oidc
from traust_ledger.auth.verifier import TokenVerifier, VerifierConfig
from traust_ledger.client import LedgerClient, LedgerError, SigningConfig

logger = logging.getLogger(__name__)

SNAPSHOT_MARKER_SUFFIX = ".snapshot"
BACKEND_DB = "db"
BACKEND_FILE = "file"
_PSYCOPG_SCHEME = "postgresql+psycopg://"


@dataclass(frozen=True)
class LayerBinding:
    """The one database layer a run reads and writes. Never derived from a path."""

    layer_id: str | None = None
    product_repo_id: str | None = None

    def __post_init__(self) -> None:
        if not self.layer_id and not self.product_repo_id:
            raise LedgerError("a layer binding needs a layer_id or a product_repo_id")

    def resolve(self, client: LedgerClient) -> str:
        """The bound layer ID; an explicit ID must belong to the bound owner."""
        owned = client.find_layer(self.product_repo_id) if self.product_repo_id else None
        if self.product_repo_id and owned is None:
            raise LedgerError(
                f"product_repo {self.product_repo_id!r} has no ledger layer; database mode "
                "never creates layers — initialize one for this product_repo (SCI or an "
                "administrator) first"
            )
        if self.layer_id and owned is not None and owned != self.layer_id:
            raise LedgerError(
                f"layer {self.layer_id!r} does not belong to product_repo "
                f"{self.product_repo_id!r} (its layer is {owned!r})"
            )
        return self.layer_id or str(owned)


@dataclass(frozen=True)
class ClientSettings:
    """Every ``LedgerClient`` argument, resolved once from ``ledger.yaml``.

    Unconfigured parts get explicit defaults (no signing requirement, a keypair
    signer without a key, no directory, the Ledger's own token verification)
    rather than the SDK's environment fallbacks.
    """

    signing_config: SigningConfig
    signing_required: bool
    directory: EmployeeDirectory | bool
    verifier: TokenVerifier | None
    dsn: str | None

    @classmethod
    def from_config(cls, ledger: LedgerConfig | None) -> ClientSettings:
        signing = (ledger.signing if ledger else None) or LedgerSigning()
        identity = (ledger.identity if ledger else None) or LedgerIdentity()
        return cls(
            signing_config=SigningConfig(
                method=signing.method,
                key_path=signing.key_path,
                oidc_issuer=signing.oidc_issuer,
                oidc_client_id=signing.oidc_client_id,
                expected_identity=signing.expected_identity,
                ca_url=signing.ca_url,
                tlog_url=signing.tlog_url,
            ),
            signing_required=signing.required,
            directory=(
                load_directory({DIRECTORY_COMMAND_ENV: identity.directory_command})
                if identity.directory_command
                else False
            ),
            verifier=_verifier(identity),
            dsn=ledger.dsn if ledger else None,
        )

    @property
    def database(self) -> bool:
        return self.dsn is not None

    def client(self, *, data_dir: Path | None = None) -> LedgerClient:
        """A ``LedgerClient`` with every argument explicit (database when ``dsn`` is set)."""
        common: dict[str, Any] = {
            "signing_config": self.signing_config,
            "signing_required": self.signing_required,
            "directory": self.directory,
            "verifier": self.verifier,
        }
        if self.dsn is not None:
            return LedgerClient(
                backend_type=BACKEND_DB, database_url=ledger_database_url(self.dsn), **common
            )
        if data_dir is None:
            raise LedgerError("file mode needs the layer's directory (data_dir)")
        return LedgerClient(backend_type=BACKEND_FILE, data_dir=str(data_dir), **common)


def _verifier(identity: LedgerIdentity) -> TokenVerifier | None:
    """Token verifier for a configured OIDC provider; None keeps the Ledger's own."""
    if not (identity.jwks_url or identity.oidc_issuer):
        return None
    jwks_url = identity.jwks_url or discover_oidc(str(identity.oidc_issuer)).jwks_uri
    return TokenVerifier(
        VerifierConfig(
            jwks_url=jwks_url, issuer=identity.oidc_issuer, audience=identity.oidc_audience
        )
    )


def ledger_database_url(dsn: str) -> str:
    """SQLAlchemy URL for the Ledger client; bare ``postgresql://`` means psycopg 3."""
    if dsn.startswith("postgresql://"):
        return _PSYCOPG_SCHEME + dsn.removeprefix("postgresql://")
    return dsn


def snapshot_marker(layer_path: Path) -> Path:
    """Sidecar that marks *layer_path* as a database snapshot, not a file ledger."""
    return layer_path.with_name(layer_path.name + SNAPSHOT_MARKER_SUFFIX)


def _write_atomic(path: Path, text: str, *, mode: int) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".snapshot.tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        Path(tmp).chmod(mode)
        Path(tmp).replace(path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


@dataclass
class VerifyResult:
    """Outcome of a layer integrity check."""

    passed: bool
    findings: list[dict] = field(default_factory=list)
    checked_at: str = ""


@dataclass
class SubmitResult:
    """Outcome of appending events to a layer."""

    event_ids: list[str] = field(default_factory=list)
    queue_added: int = 0


class LedgerService:
    """Stateful gateway to traust-ledger operations.

    Delegates to ``LedgerClient`` for all authenticated ledger I/O. Build it with
    ``engine.ledger.service(…)``, which takes the mode, signing and identity from
    the injected context; the constructors below are what that uses.

    Usage:
        ledger = engine.ledger.service(layer_path.parent)   # file mode
        ledger = engine.ledger.service(layer=binding)        # ledger.yaml dsn set

        ledger.submit_events(layer_path, events)
        result = ledger.query_findings(layer_path)
        ledger.verify(layer_path)

    In database mode ``layer_path`` only names where the snapshot is written;
    the layer itself is the bound database layer.
    """

    def __init__(
        self,
        client: LedgerClient | None = None,
        *,
        data_dir: Path | None = None,
        settings: ClientSettings | None = None,
        binding: LayerBinding | None = None,
    ):
        """File mode under *data_dir*, or an injected *client* (with *binding*: database).

        *settings* defaults to :meth:`ClientSettings.from_config` with no
        ``ledger.yaml``: explicit defaults, never environment fallbacks.
        """
        self._binding = binding
        self._bound_id: str | None = None
        self._bound_path: Path | None = None
        if client is not None:
            self._client = client
            self._database = binding is not None
            return
        if binding is not None:
            raise LedgerError("a layer binding needs a database client; use LedgerService.database")
        settings = settings or ClientSettings.from_config(None)
        if settings.database:
            raise LedgerError("ledger.yaml sets a dsn: use LedgerService.database with a binding")
        self._database = False
        self._client = settings.client(data_dir=data_dir)

    @classmethod
    def database(cls, settings: ClientSettings, binding: LayerBinding) -> LedgerService:
        """Database mode on the configured ``dsn``, bound to one layer."""
        if not settings.database:
            raise LedgerError("database mode needs ledger.yaml dsn")
        return cls(client=settings.client(), binding=binding)

    @property
    def database_mode(self) -> bool:
        return self._database

    def _layer(self, layer_path: Path) -> str:
        """Ledger layer ID: the bound database layer, or the file's stem in file mode.

        Database mode binds one layer *and* one snapshot path per service: a second,
        different path would otherwise silently read or write the bound layer under
        another repo's name.
        """
        if not self._database:
            return layer_path.stem
        path = layer_path.resolve()
        if self._bound_path is None:
            self._bound_path = path
        elif path != self._bound_path:
            raise LedgerError(
                f"database mode binds one layer per run: {self._bound_path} is already "
                f"bound, refusing {path}; bind each layer separately"
            )
        if self._bound_id is None:
            assert self._binding is not None
            self._bound_id = self._binding.resolve(self._client)
            logger.info(
                "ledger database mode bound layer_id=%s product_repo_id=%s snapshot=%s",
                self._bound_id,
                self._binding.product_repo_id,
                path,
            )
        return self._bound_id

    def _write_target(self, layer_path: Path) -> str:
        """Layer ID for a write. File mode refuses to write over a database snapshot."""
        if not self._database and snapshot_marker(layer_path).exists():
            raise LedgerError(
                f"{layer_path} is a read-only database snapshot "
                f"(see {snapshot_marker(layer_path).name}); writing it in file mode would "
                "fork the ledger. Configure ledger.yaml and pass the run's layer binding, "
                "or remove the marker to adopt the file as a standalone ledger"
            )
        return self._layer(layer_path)

    def _refresh(self, layer_path: Path) -> None:
        """Database mode: re-export the snapshot after a committed write.

        The write is already durable, so a failed export must not invite a retry:
        the stale snapshot is removed instead (a reader then fails loudly rather
        than read old state) and the next read re-exports it.
        """
        if not self._database:
            return
        try:
            self.write_snapshot(layer_path)
        except OSError as exc:
            logger.warning(
                "ledger write committed but snapshot refresh failed layer_id=%s path=%s: %s",
                self._bound_id,
                layer_path,
                exc,
            )
            for stale in (layer_path, snapshot_marker(layer_path)):
                with contextlib.suppress(OSError):
                    stale.unlink(missing_ok=True)

    def write_snapshot(self, layer_path: Path) -> dict:
        """Export the bound database layer to *layer_path* atomically; return it.

        The file is a read-only view for sessions and file readers. Its metadata
        carries the ``merkle_root``/``merkle_size`` it was taken at, so a stale
        snapshot is detectable. File mode has nothing to export.
        """
        if not self._database:
            raise LedgerError("write_snapshot needs database mode")
        layer_id = self._layer(layer_path)
        try:
            layer = self._client.get_layer(layer_id)
        except LedgerError as exc:
            raise LedgerError(
                f"{exc}; database mode never creates layers — initialize {layer_id!r} "
                "for its product_repo (SCI or an administrator) first"
            ) from exc
        text = json.dumps(layer, indent=2, ensure_ascii=True) + "\n"
        marker = snapshot_marker(layer_path)
        unchanged = (
            layer_path.is_file()
            and marker.is_file()
            and layer_path.read_text(encoding="utf-8") == text
        )
        if unchanged:
            return layer  # no rewrite: keeps mtime and git status meaningful
        layer_path.parent.mkdir(parents=True, exist_ok=True)
        meta = layer.get("metadata") or {}
        _write_atomic(
            marker,
            json.dumps(
                {
                    "layer_id": layer_id,
                    "merkle_root": meta.get("merkle_root"),
                    "merkle_size": meta.get("merkle_size"),
                    "exported_at": datetime.now(UTC).isoformat(timespec="seconds"),
                },
                indent=2,
            )
            + "\n",
            mode=0o444,
        )
        _write_atomic(layer_path, text, mode=0o444)
        logger.info(
            "ledger snapshot exported layer_id=%s merkle_size=%s path=%s",
            layer_id,
            meta.get("merkle_size"),
            layer_path,
        )
        return layer

    # ─── Ledger operations (delegate to LedgerClient → Backend) ─────────

    def actor(self):
        """The verified actor this service writes as: the ledger identity
        token, verified, with the deployment's optional employee-directory
        cross-check applied (``LEDGER_DIRECTORY_COMMAND``). Raises
        ``LedgerError`` when either refuses. Callers that record human
        decisions resolve this once, up front, so a refusal happens before
        any work — the SDK re-derives the same actor at submit time."""
        return self._client.actor()

    def query_findings(self, layer_path: Path) -> dict[str, Any]:
        """Resolve current dispositions for all findings in a layer."""
        return self._client.query_findings(self._layer(layer_path))

    def verify(self, layer_path: Path, *, check_signatures: bool = False) -> VerifyResult:
        """Verify Merkle integrity (and optionally signatures) of a layer."""
        result = self._client.verify(self._layer(layer_path), check_signatures=check_signatures)
        return VerifyResult(
            passed=result.get("passed", False),
            findings=result.get("findings", []),
            checked_at=result.get("checked_at", ""),
        )

    def submit_events(
        self,
        layer_path: Path,
        events: list[dict],
        *,
        report_path: Path | None = None,
        queue_items: list[dict] | None = None,
    ) -> SubmitResult:
        """Append events to a layer via LedgerClient.

        Deduplication, actor stamping, Merkle finalization, and signing
        are handled by the SDK's submit handler.
        """
        layer_id = self._write_target(layer_path)
        result = self._client.submit(
            layer_id,
            events,
            needs_review=queue_items,
        )

        if report_path is not None:
            digest = reports.report_sha256(str(report_path))
            self._client.patch_metadata(
                layer_id,
                {
                    "audit_report_sha256": digest,
                },
            )

        self._refresh(layer_path)
        return SubmitResult(
            event_ids=result.get("event_ids", []),
            queue_added=result.get("queue_added", 0),
        )

    def sign(self, layer_path: Path, *, rekor: bool = False) -> None:
        """Stamp Merkle metadata and sign a layer file."""
        self._client.sign(self._write_target(layer_path), rekor=rekor)
        self._refresh(layer_path)

    def resolve_review_item(
        self,
        layer_path: Path,
        key: str,
        decision: str,
        note: str = "",
    ) -> dict:
        """Mark a review queue item as resolved."""
        result = self._client.resolve(self._write_target(layer_path), key, decision, note)
        self._refresh(layer_path)
        return result

    def countersign(
        self,
        layer_path: Path,
        finding_ref: str,
        *,
        rationale: str,
        recorded_at: str,
        decision: str | None = None,
        severity: str | None = None,
        actor: LayerActor | None = None,
    ) -> dict:
        """Record a human countersign/severity event through the gated SDK handler.

        The SDK runs the human-lane gates, stamps the actor, and signs
        atomically — the harness never appends or signs events itself.
        """
        result = self._client.countersign(
            self._write_target(layer_path),
            finding_ref,
            rationale=rationale,
            recorded_at=recorded_at,
            decision=decision,
            severity=severity,
            actor=actor,
        )
        self._refresh(layer_path)
        return result

    def whoami(self) -> LayerActor:
        """The verified actor for the current token (see LedgerClient.whoami)."""
        return self._client.whoami()

    # ─── Layer file I/O (file mode: the file; database mode: the snapshot) ──

    def read_layer_file(self, layer_path: Path) -> dict:
        """Load the layer. File mode reads the JSON file; database mode reads the
        bound layer from the database and refreshes the snapshot at *layer_path*."""
        if self._database:
            return self.write_snapshot(layer_path)
        if snapshot_marker(layer_path).exists():
            logger.warning(
                "reading a database snapshot in file mode (writes will be refused): %s",
                layer_path,
            )
        return json.loads(layer_path.read_text(encoding="utf-8"))

    def ensure_layer_file(self, layer_path: Path, *, shell: dict | None = None) -> dict:
        """Load or create a layer via LedgerClient. Returns the layer dict.

        Database mode never creates: the bound layer must already exist
        (initialized or imported by SCI/an administrator for its product_repo).
        """
        if self._database:
            return self.write_snapshot(layer_path)
        layer_id = self._write_target(layer_path)  # refuses a snapshot before any write
        try:
            return self.read_layer_file(layer_path)
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        base = shell or {"events": [], "metadata": {}}
        self._client.create(layer_id, shell=base)
        return dict(base)

    def patch_layer_file(
        self,
        layer_path: Path,
        updates: dict[str, Any],
        *,
        sign: bool = True,
    ) -> None:
        """Merge *updates* into layer metadata atomically via LedgerClient.

        Used by baseline_claims (claim_hashes), route_regressions (claim_hashes),
        and countersign (finding_aliases). Atomic: mutate + stamp + sign in one
        Backend.mutate call.

        First writes and new keys only for signature-bound fields
        (``claim_hashes``, ``audit_report_sha256``, ``artifact_digests``): the
        ledger refuses to overwrite a value it already signed. Use
        :meth:`restate` for that.

        *sign* parameter is accepted for backward compat but ignored — writes
        are always atomic (stamped + signed) through the SDK.
        """
        self._client.patch_metadata(self._write_target(layer_path), updates)
        self._refresh(layer_path)

    def restate(
        self,
        layer_path: Path,
        *,
        target: str,
        before: Any,
        after: Any,
        rationale: str,
        ticket: str,
        reason: str = "baseline_rewrite",
        approved_by: str | None = None,
        finding_ref: str | None = None,
    ) -> dict[str, Any]:
        """Overwrite a signature-bound metadata value through a recorded restatement.

        The one sanctioned way to change ``claim_hashes``, ``audit_report_sha256``
        or ``artifact_digests`` once signed: the prior value, the verified actor,
        the ticket and the rationale are appended inside the Merkle tree, the
        value is applied, and the layer re-signs — atomically. For map targets
        ``before``/``after`` carry only the changed keys.
        """
        authority: dict[str, Any] = {"ticket": ticket}
        if approved_by:
            authority["approved_by"] = approved_by
        block = {
            "target": target,
            "reason": reason,
            "before": before,
            "after": after,
            "authority": authority,
        }
        result = self._client.restate(
            self._write_target(layer_path), block, rationale=rationale, finding_ref=finding_ref
        )
        self._refresh(layer_path)
        return result

    def stamp_report_file(self, layer_path: Path, report_path: Path, *, sign: bool = True) -> bool:
        """Pin audit_report_sha256 for *report_path* in the layer.

        Returns True when a digest was written, False when the layer already
        holds this report's digest. A layer pinned to *different* report bytes
        is refused: replacing a signed digest needs :meth:`restate`
        (``target="audit_report_sha256"``) so the change is explained.
        *sign* accepted for backward compat but ignored — writes are atomic.
        """
        digest = reports.report_sha256(str(report_path))
        current = (self.read_layer_file(layer_path).get("metadata") or {}).get(
            "audit_report_sha256"
        )
        if current == digest:
            return False
        if current:
            raise LedgerError(
                f"{layer_path.name} pins a different audit report "
                f"({current[:12]}…, now {digest[:12]}…) — restate "
                "audit_report_sha256 with a ticket and rationale instead of re-stamping"
            )
        self._client.patch_metadata(self._write_target(layer_path), {"audit_report_sha256": digest})
        self._refresh(layer_path)
        return True

    def stamp_event_identities(self, layer_path: Path, fingerprints: dict[str, str]) -> int:
        """Backfill event fingerprints and re-sign atomically via the SDK.

        The skill hands the fingerprint map (finding_ref -> fp) to the ledger,
        which stamps identity onto the events inside the Merkle tree and re-signs
        in one atomic write — the skill never writes the layer itself. Returns
        the number of events stamped.
        """
        result = self._client.stamp_event_identities(self._write_target(layer_path), fingerprints)
        self._refresh(layer_path)
        return int(result.get("stamped", 0))

    def store_layer(self, layer_path: Path, layer: dict) -> None:
        """Persist a complete layer dict through the backend.

        Use when a caller has built an entire layer in memory and needs
        to write it before signing.  Typical pattern::

            svc.store_layer(layer_path, layer)
            svc.sign(layer_path)          # stamps + signs atomically
        """
        self._client.store(self._write_target(layer_path), layer)

    # ─── Utilities ───────────────────────────────────────────────────────

    def layer_id_for(self, layer_path: Path) -> str:
        """The ledger layer ID this service uses for *layer_path* (bound ID in database mode)."""
        return self._layer(layer_path)

    @staticmethod
    def layer_id_from_path(layer_path: Path) -> str:
        """File-mode layer ID (stem without extension). Use :meth:`layer_id_for` instead."""
        return layer_path.stem

    @staticmethod
    def review_item_key(item: dict) -> str:
        """Compute the addressable key for a review queue item.

        Returns a JSON string ready to pass to :meth:`resolve_review_item`.
        """
        key = (
            item.get("source_ref"),
            item.get("suggested_finding_ref"),
            item.get("queue_reason"),
            item.get("quote"),
        )
        return json.dumps(list(key))


__all__ = [
    "ClientSettings",
    "LayerBinding",
    "LedgerClient",
    "LedgerError",
    "LedgerService",
    "SubmitResult",
    "VerifyResult",
    "ledger_database_url",
    "snapshot_marker",
]
