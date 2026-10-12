# Changelog

All notable changes to traust-engine are documented here.

## [0.21.0]

## Changes

- **The ledger mode comes from the injected context, never the environment.**
  `ledger.yaml` with a `dsn` (`HarnessContext.ledger`, traust-contracts 0.53.0):
  the Ledger database is the authority, and `engine.ledger.service(…, layer=…)` /
  `engine.ledger.pull(path, layer)` work on the one layer the caller binds.
  No `dsn` (or no `ledger.yaml`): file mode, as before. `LedgerService` no longer reads
  `LAAS_BACKEND_TYPE`, `LAAS_DATABASE_URL`, `TRAUST_LEDGER_LAYER_ID` or
  `TRAUST_LEDGER_PRODUCT_REPO_ID`; those variables cannot switch its mode.
- `LedgerService.database(dsn, binding)` builds database mode explicitly;
  `LedgerService(data_dir=…)` is always file mode. A bare `postgresql://` DSN is
  used through psycopg 3.
- `LedgerOps.service` refuses a missing binding when `ledger.yaml` sets a
  `dsn`, and a binding when it does not; `LayerBinding()` without a
  `layer_id` or `product_repo_id` is refused at construction.
- **Signing and identity come from `ledger.yaml` too**, in both modes:
  `signing` builds the Ledger `SigningConfig` and `signing_required`;
  `identity` builds the token verifier (issuer, audience, JWKS or discovery)
  and the employee-directory cross-check (fail closed if the command is
  missing). Configured values win over `LAAS_SIGNING_*` / `LEDGER_OIDC_*` /
  `LEDGER_DIRECTORY_COMMAND`; unconfigured parts keep the Ledger's defaults.
  Secrets (the caller's ledger token, keypair password, an ambient keyless
  signing token) still come from the runner.
- `LedgerService.database(ledger_config, binding)` takes the config section.
- `engine.ledger.bind(layer)` sets the run's layer once at the entry point (a
  CLI argument); later `service()` / `pull()` calls without their own `layer`
  use it, and rebinding to a different layer is refused.
- Pins traust-contracts 0.53.0 and traust-ledger 0.11.1.
- Snapshot, single-path and file-mode guards from 0.20.0 are unchanged.

## [0.20.0]

## Changes

- **`LedgerService` database mode.** With `LAAS_BACKEND_TYPE=db` and
  `LAAS_DATABASE_URL`, the Ledger database is the authority: the run is bound to
  one layer (`TRAUST_LEDGER_LAYER_ID` and/or `TRAUST_LEDGER_PRODUCT_REPO_ID`, an
  explicit ID must belong to the owner), every read and write goes to it, and
  the layer file becomes a read-only snapshot re-exported after each read and
  write. Countersigns written to the database out of band (e.g. from SCI) are
  visible to the next read. Database mode never creates a layer and never
  falls back to the file; a missing URL or binding fails the call.
- **Database-mode guards.** One service binds one layer *and* one snapshot
  path; a second path is refused instead of reading or writing the bound
  layer under another repo's name. Each snapshot carries a read-only
  `<layer>.snapshot` marker (layer ID, Merkle root/size, export time), and
  file mode refuses to write or initialize a marked file, so a process that
  lost the database environment cannot fork the ledger on disk. An unchanged
  snapshot is not rewritten (mtime and git status stay meaningful). If a
  committed write's snapshot refresh fails, the stale snapshot is removed
  and the call does not raise. A missing layer says who creates it. Binding
  and export are logged (`traust_engine.ledger.service`, INFO; never the DSN).
- `LedgerService.write_snapshot`, `LedgerService.layer_id_for`,
  `LedgerOps.pull`, and `LayerBinding` (exported from `traust_engine.ledger`).
- File mode is unchanged and now pins `backend_type="file"`, so a stray
  environment cannot switch backends silently.
- **Migration always imports layers into the Ledger.** `migrate_cli` imports
  selected layer artifacts into `traust_ledger` in the same migration database
  after artifact reconciliation (SQLite file or the PostgreSQL DSN); layers are
  never routed to artifact storage. `--layer-destination`,
  `--ledger-target-url-env` and their config keys are removed, `make migrate-*`
  installs the `ledger-migration` extra, and local `migration.yaml` is
  gitignored.
- Pins traust-ledger 0.11.0 (`get_layer`/`find_layer`, traust-ledger#82) and
  traust-contracts 0.52.0, both from `traust-security`.

## [0.19.3]

## Changes

- Record projection rows as contracts writes them, reject dropped rows by rowcount, and
  verify evidence, bindings and projection values in one bulk pass at reconciliation
  instead of re-projecting and reading back each artifact.
- Replace the SQLite and PostgreSQL rehearsal databases with one `MigrationTarget`.
- Share one database-free resolve step between preview and load; record per-phase timing.
- Type migration decisions and plans; migration modules pass `mypy --strict`.

## [0.19.2]

## Changes

- Add bounded, opt-in spawned validation processes while retaining deterministic
  decisions and ordered single-connection database writes.
- Index directory ownership, cache exact repository registrations and prepared
  bindings, and avoid repeating schema validation for hash-verified bytes.
- Expose validation/registration phase progress and exclude derived PostgreSQL
  views from physical projection counts during final reconciliation.

## [0.19.1]

## Changes

- Add opt-in `migration.multi_ref_policy: newest` for unqualified companion
  ownership. Rank recorded baseline audit dates, preserve explicit branches,
  block cross-ref ties and missing dates, and record the selected audit/ref.
- Do not reassign historical reports, triages or Ledger histories to a newer
  branch without an exact baseline binding. Default ambiguity handling is unchanged.

## [0.19.0]

## Changes

- Import filesystem product/repo/ref relationships into the contracts 0.50.0 registry
  before ingesting artifacts; bind repository IDs and commit SHAs to evidence.
- Export ledger selections with product_repo IDs, or import them into a selected
  ledger target after storage reconciliation (`ledger-migration` extra).
- Pin traust-contracts 9e5e6605 and traust-ledger 5c326338; bootstrap fresh
  storage with `Store.migrate()`.

## [0.18.2]

## Changes

- **Fix:** `render` writes a threat model's update history inside section 7.
  It was written at the end of the document, which only fell inside section 7
  while nothing came after it. On an OWASP-rated model it landed in section 11,
  and lint rejected it.
- **Fix:** `render` writes an asset's optional `regulatory_scope` and
  `example_records` columns when any asset carries them; they were dropped.
- **Fix:** attack-scenario steps render as prose paragraphs, as `schema.md`
  section 9 specifies, instead of bullets.
- traust-contracts 0.47.0 (every threat-model section defined) and
  traust-ledger 0.8.5.

## [0.18.1]

## Changes

- traust-contracts v0.46.0 (OWASP risk ratings in the storage `threat` table)
  and traust-ledger 0.8.4. Ingesting a rated threat model now fills the
  threat `severity`, score, level and basis columns. Nothing else changes.

## [0.18.0]

## Changes

- **Threat models rated with the OWASP Risk Rating Methodology.** Pins
  traust-contracts v0.45.0, whose threat schema adds `risk_rating`, and
  traust-ledger 0.8.3 (the same contracts pin). The arithmetic stays in
  `traust_contracts.v1.risk_rating`. The new `reporting/threat_rating.py` owns
  how a rating is written in Markdown and read back:
  - `render` gives a rated model `severity | likelihood | impact` columns
    (`high | medium 4.375 | high 7.25 technical`) and a section 11,
    "Risk ratings", with every factor score and its reason. A threat not yet
    re-rated shows `unrated | legacy <label> | legacy <label>`. Legacy models
    render exactly as before.
  - `lint` accepts the rated variant. It checks that each level matches its
    score and that severity follows from the levels, and it recomputes every
    rating from its section 11 factors.
  - `validate` rejects a threat-model JSON whose rating scores, levels or
    severity disagree with its factors, which a JSON Schema can't express.
  - `corpus.threat_model.parse_threats` returns `severity` and
    `severity_source`, plus the scores and basis for rated rows. It drops the
    home-grown `score` (impact weight × likelihood weight).
  - Legacy labels are ordered on the OWASP table by a fixed crosswalk until
    each model is re-rated. The crosswalk is used only for ordering, is never
    written back as a rating, and is reported as
    `severity_source: legacy-crosswalk`.

## [0.17.0]

## Changes

- **`locations.analysis_results` chooses where reports live.** A path or
  `file://` stays on local disk; an `s3://` / `gs://` URI goes through fsspec
  (`traust-engine[s3]` / `[gcs]`, configured by the existing `HARNESS_S3_*`
  env). New `report_store.open_backend(location)` picks the backend and
  `FsspecBackend` implements it; `engine.corpus.report_store()` and
  `corpus.precedent` use it instead of hard-coding `LocalBackend`.
  `storage.filesystem(uri)` is public, and a missing scheme driver is a
  `StorageError` naming the extra rather than fsspec's `ImportError`.
- Remote `analysis_results` covers verified reads and writes through
  `ReportStore`; ingest and resolution still walk a local tree.
- `FsspecBackend` failures are `StorageError`, never "absent": `exists()` no
  longer returns `False` on bad credentials or an unreachable endpoint,
  `list()` wraps backend errors, and a missing bucket fails at construction
  instead of reading as "report not found". Only writable schemes (`s3`,
  `gs`/`gcs`, `az`/`abfs`) are accepted as a report location; `http(s)://` is
  refused up front. `SoundnessResolver` refuses a remote `analysis_results`
  (precedent resolution is local-only) instead of treating `s3://b/p` as a
  local folder.
- Pins: traust-contracts 0.44.0 (from 0.35.0), traust-ledger 0.8.2 (from
  0.6.32). 0.8.2 makes `LedgerClient.restate()` usable in-process (0.8.0/0.8.1
  always refused it) and pins SDK OIDC verification to the configured issuer.
- **`LedgerService.restate()`**: the only way to overwrite a signed
  `claim_hashes` / `audit_report_sha256` / `artifact_digests` value. The prior
  value, verified actor, ticket and rationale are recorded in the layer.
  `patch_layer_file` still does first writes and new keys only.
- `LedgerService.stamp_report_file()` pins `audit_report_sha256` once and
  returns `False` when it's unchanged. It refuses to overwrite a different
  pinned digest (use `restate`) instead of re-patching unconditionally, which
  ledger ≥0.8 refuses mid-write.
- **Consumers: ledger writes now need a verifiable identity.** Ledger ≥0.7
  verifies the actor before `sign()` / `patch_metadata()` /
  `stamp_event_identities()`, so a placeholder token (`token="test-token"`)
  is refused. Configure OIDC (`LEDGER_OIDC_ISSUER` / `LEDGER_OIDC_JWKS_URL`)
  or local auth (`LEDGER_LOCAL_IDENTITY`, or `ledger auth local`); test
  suites can set `LEDGER_LOCAL_IDENTITY` in an isolated `HOME`. Ledger 0.8
  also refuses to sign a layer without an initialized shell (`audit_report`,
  `repository`, `created`, `harness_version`). `finding_identity.rebaseline`
  is unchanged; its tests now supply a verifier, a complete layer shell, and
  sha256-shaped claim hashes.

## [0.3.0]

## Changes

- **Reverted the 0.15.0 findings.db changes.** `findings_db` builds the
  previous nine-table projection again (`SCHEMA_REVISION` 3), `store_ingest`
  and the SLA view are as in 0.13.3. Pins: contracts 0.35.0 (the 0.33.0
  storage contract), ledger 0.6.32. 0.15.0 remains tagged and should not be
  pinned.

## [0.2.5]

- Pin traust-contracts v0.5.0 (evidence projection + postgres storage
  namespace) and traust-ledger v0.3.0 (stamp + whoami over REST).

## [0.2.4]

- Point the traust-contracts and traust-ledger pins at the new
  `traust-security` GitHub organisation (ledger v0.2.3, which carries the
  corrected URL inside its own tag).

## [0.2.3]

- Pin traust-contracts v0.4.0 and traust-ledger v0.2.2, carrying the typed
  patch-evidence block on the VERIFICATION family through to the report
  validator. No engine logic changes: `reporting/validate.py` validates
  against the pinned schema, so accepting the block on a verification report
  is a consequence of the pin.

## [0.2.2]

- Pin traust-contracts v0.3.0 and traust-ledger v0.2.1, carrying the optional
  `evidence[]` block on remediation reports through to the report validator.
  No engine logic changes: `reporting/validate.py` validates against the
  pinned schema, so accepting the block is a consequence of the pin. The
  existing cross-check tying `summary.status == 'revalidated_fixed'` to
  `revalidation.fixed` is untouched, since no status depends on `evidence[]`
  yet.

## [0.2.0]

## Changes

- delegate countersign/whoami/stamp_event_identities to the engine

## [0.1.1]

## Changes

- Adopt traust-contracts 0.1.1 and traust-ledger 0.1.1, which enforce RFC
  3339 on `LayerEvent.recorded_at` / `.occurred_at`. No engine code changes
  were needed — dependency pins only.

### Upgrading

Contracts 0.1.1 validates timestamps on read as well as write, so a corpus
holding non-conforming values must be migrated before this release is used
against it (`python3 -m traust.migrations.fix_event_timestamps <root>
--apply`). `traust_engine.reporting.validate` also asserts `format:
date-time` now that the format assertor ships as a declared dependency.

## [0.1.0]

Self-contained processing library for Traust: deterministic workflow code
for disposition merge, validation gates, and rule calibration — the
`traust_engine` package consumed by the app CLI and other components.
