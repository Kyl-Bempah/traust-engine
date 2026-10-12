"""``HarnessEngine.ledger`` — LedgerService gateway, bound to context.

The ledger mode comes from the injected context, never the environment:
``ctx.ledger.dsn`` (``ledger.yaml``) set means the Ledger database is the
authority and every service is bound to the one layer the caller names;
otherwise layer files are the ledger.
"""

from __future__ import annotations

from functools import cached_property
from pathlib import Path

from traust_ledger.client import LedgerError

from traust_engine import locations
from traust_engine._ops_base import ContextOps
from traust_engine.ledger.service import ClientSettings, LayerBinding, LedgerService


class LedgerOps(ContextOps):
    _run_layer: LayerBinding | None = None

    def bind(self, layer: LayerBinding) -> None:
        """Set the run's layer once at the entry point (a CLI argument, never env).

        Every later :meth:`service` / :meth:`pull` call without its own *layer*
        uses it, so deep callers need not thread the binding through. Binding a
        different layer later in the same run is refused.
        """
        if self._run_layer is not None and self._run_layer != layer:
            raise LedgerError(f"run already bound to {self._run_layer}; refusing {layer}")
        self._run_layer = layer

    def signing_pubkey(self) -> Path | None:
        return self._ctx.signing_pubkey

    @cached_property
    def settings(self) -> ClientSettings:
        """Ledger client settings from ``ledger.yaml``, resolved once per context."""
        return ClientSettings.from_config(self._ctx.ledger)

    @property
    def database_configured(self) -> bool:
        """True when ``ledger.yaml`` sets ``dsn``: the Ledger database is the authority."""
        return self.settings.database

    def _default_data_dir(self) -> Path | None:
        ar = locations.analysis_results_dir(self._loc)
        if ar is not None:
            return ar
        return locations.local_path(self._loc.workspace if self._loc else None)

    def service(
        self, data_dir: Path | None = None, *, layer: LayerBinding | None = None
    ) -> LedgerService:
        """Return a :class:`LedgerService` for this deployment.

        *layer* defaults to the run binding from :meth:`bind`. With ``ledger.yaml``
        ``dsn`` set, a layer is required and the service works on that database
        layer (*data_dir* is unused). Otherwise the service is file mode under
        *data_dir* — defaulting to ``locations.analysis_results``, else
        ``locations.workspace`` — and a layer binding is an error, since there is
        no database to bind to.
        """
        layer = layer or self._run_layer
        if self.settings.database:
            if layer is None:
                raise LedgerError(
                    "ledger.yaml sets a dsn: pass the run's layer binding (layer_id or "
                    "product_repo_id); the database ledger is never addressed by file name"
                )
            return LedgerService.database(self.settings, layer)
        if layer is not None:
            raise LedgerError("a layer binding was given but ledger.yaml sets no dsn")
        resolved = data_dir if data_dir is not None else self._default_data_dir()
        if resolved is None:
            raise LedgerError(
                "no layer directory: pass the layer's directory or set "
                "locations.analysis_results / locations.workspace"
            )
        return LedgerService(data_dir=resolved, settings=self.settings)

    def pull(self, layer_path: Path, layer: LayerBinding | None = None) -> dict:
        """Export the bound database layer to *layer_path* as the session snapshot."""
        return self.service(layer=layer).write_snapshot(layer_path)
