"""The tick: route repositories whose inputs changed, then plan every asset that is due."""

from __future__ import annotations

import logging
from collections.abc import Callable, Collection
from datetime import datetime, timedelta
from typing import Generic, TypeVar
from uuid import UUID

import pydantic
from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.base import Model
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.operations import (
    OPEN_ORDER_STATES,
    AssetName,
    OrderRequest,
    OrderState,
)
from traust_core.v1.models.vocabulary import ActorKind
from traust_core.v1.providers.clock import Clock
from traust_core.v1.services.operations import OpsService, Router

from traust_engine.pack import Pack

log = logging.getLogger(__name__)

S = TypeVar("S")

ENGINE = Principal(identity="traust-engine", kind=ActorKind.MACHINE, display="traust-engine")
MATERIALIZED = (OrderState.SUCCEEDED, OrderState.DEGRADED)
# A refused or failed run waits out the cadence too, so a broken asset can't spin every tick.
ATTEMPTED = (*MATERIALIZED, OrderState.REFUSED, OrderState.FAILED)


class TickReport(Model):
    planned: int = 0
    routed: int = 0
    unrouted: int = 0
    stale: dict[AssetName, int] = pydantic.Field(default_factory=dict)


class Controller(Generic[S]):
    def __init__(
        self,
        pack: Pack,
        ops: OpsService,
        clock: Clock,
        router: Router[S, object] | None = None,
        state_of: Callable[[UUID], S] | None = None,
    ) -> None:
        if (router is None) != (state_of is None):
            raise ValueError("a router needs state_of, and state_of needs a router")
        self._pack = pack
        self._ops = ops
        self._clock = clock
        self._router = router
        self._state_of = state_of
        self._routed_until: datetime | None = None

    def tick(self, repositories: Collection[UUID]) -> TickReport:
        now = self._clock.now()
        routed, unrouted = self._route(now)
        planned, stale = 0, {}
        for name in self._pack.topo_order():
            spec = self._pack.assets[name]
            if spec.every is None:
                continue
            subjects: Collection[UUID | None] = repositories if spec.partitions else (None,)
            busy = self._ops.subjects(name, OPEN_ORDER_STATES) | self._ops.subjects(
                name, ATTEMPTED, now - spec.every
            )
            fresh = {dep: self._fresh(dep, now) for dep in spec.deps}
            for subject in subjects:
                if subject in busy:
                    continue
                if any(self._dep_subject(dep, subject) not in ok for dep, ok in fresh.items()):
                    stale[name] = stale.get(name, 0) + 1
                    continue
                self._ops.plan(
                    OrderRequest(asset=name, priority=spec.priority, repository_id=subject), ENGINE
                )
                planned += 1
        for name, count in stale.items():
            log.warning("%s: %d subjects wait on stale upstreams; not planned", name, count)
        log.info("tick planned %d orders, routed %d repositories", planned, routed)
        return TickReport(planned=planned, routed=routed, unrouted=unrouted, stale=stale)

    def _route(self, now: datetime) -> tuple[int, int]:
        """Re-route only repositories whose `route_on` asset materialized since the last tick."""
        source = self._pack.route_on
        if self._router is None or self._state_of is None or source is None:
            return 0, 0
        since = self._routed_until or now - (self._pack.assets[source].every or timedelta())
        changed = self._ops.subjects(source, MATERIALIZED, since)
        routed = unrouted = 0
        for repository_id in (r for r in changed if r is not None):
            try:
                state = self._state_of(repository_id)
            except NotFoundError as e:
                log.warning("not routed: %s", e)
                unrouted += 1
                continue
            # NEED(feed): injected events and refusals come from the feed once it lands.
            route = self._router.route(state, (), ())
            if route.lane is not None:
                asset = self._pack.asset_for_lane(route.lane)
                request = OrderRequest(
                    asset=asset,
                    priority=route.priority,
                    repository_id=repository_id,
                    lane=route.lane,
                    rule=route.reason,
                )
                self._ops.plan(request, ENGINE)
            routed += 1
        self._routed_until = now
        return routed, unrouted

    def _fresh(self, dep: AssetName, now: datetime) -> set[UUID | None]:
        every = self._pack.assets[dep].every
        return self._ops.subjects(dep, MATERIALIZED, None if every is None else now - every)

    def _dep_subject(self, dep: AssetName, subject: UUID | None) -> UUID | None:
        return subject if self._pack.assets[dep].partitions else None
