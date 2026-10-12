"""``HarnessEngine.ledger`` — LedgerService gateway, bound to context."""

from __future__ import annotations

from pathlib import Path

from traust_engine import locations
from traust_engine._ops_base import ContextOps
from traust_engine.ledger.service import LedgerService


class LedgerOps(ContextOps):
    def signing_pubkey(self) -> Path | None:
        return self._ctx.signing_pubkey

    def _default_data_dir(self) -> Path | None:
        ar = locations.analysis_results_dir(self._loc)
        if ar is not None:
            return ar
        return locations.local_path(self._loc.workspace if self._loc else None)

    def service(self, data_dir: Path | None = None) -> LedgerService:
        """Return a :class:`LedgerService` for this deployment.

        When *data_dir* is omitted, use ``locations.analysis_results`` if set,
        else ``locations.workspace``. Callers signing a specific layer file should
        pass ``layer_path.parent`` (the pattern used by disposition emitters).

        In database mode (``LAAS_BACKEND_TYPE=db``) the service ignores *data_dir*
        and works on the run's bound database layer; see :mod:`.service`.
        """
        resolved = data_dir if data_dir is not None else self._default_data_dir()
        if resolved is not None:
            return LedgerService(data_dir=resolved)
        return LedgerService()

    def pull(self, layer_path: Path) -> dict:
        """Database mode: export the bound layer to *layer_path* as the session snapshot."""
        return self.service(layer_path.parent).write_snapshot(layer_path)
