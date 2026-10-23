"""One pass of the continuous-ops loop: reap expired leases, tick, admit."""

from __future__ import annotations

from collections.abc import Callable
from typing import Generic, TypeVar
from urllib.parse import urlsplit
from uuid import UUID

from traust_core.v1.context.context import Services
from traust_core.v1.models.base import Model
from traust_core.v1.models.common import every_item
from traust_core.v1.models.inventory import RepositoryFilter
from traust_core.v1.providers.clock import Clock
from traust_core.v1.services.operations import Router

from traust_engine.ops.admission import Admission, AdmissionReport
from traust_engine.ops.controller import Controller, TickReport
from traust_engine.ops.pack import Pack

S = TypeVar("S")


class PassReport(Model):
    requeued: int
    tick: TickReport
    admission: AdmissionReport


class EngineLoop(Generic[S]):
    def __init__(
        self,
        services: Services,
        clock: Clock,
        pack: Pack,
        router: Router[S, object] | None = None,
        state_of: Callable[[UUID], S] | None = None,
    ) -> None:
        self._services = services
        self._controller = Controller(pack, services.ops, clock, router, state_of)
        self._admission = Admission(pack, services.ops, services.spend, clock)

    def run_once(self) -> PassReport:
        requeued = self._services.ops.requeue_expired()
        hosts = self._hosts()
        tick = self._controller.tick(hosts.keys())
        return PassReport(requeued=requeued, tick=tick, admission=self._admission.admit(hosts))

    def _hosts(self) -> dict[UUID, str]:
        portfolio = self._services.portfolio
        repositories = every_item(lambda p: portfolio.list_repositories(RepositoryFilter(), p))
        return {r.id: urlsplit(r.url).hostname or "" for r in repositories if r.id}
