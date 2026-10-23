"""Admission: one pass over the planned orders per tick, most important first."""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from uuid import UUID

from traust_core.v1.models.base import Model
from traust_core.v1.models.common import every_item
from traust_core.v1.models.operations import (
    AssetName,
    Budget,
    BudgetVerdict,
    LaneName,
    OrderFilter,
    OrderState,
    RunOrder,
)
from traust_core.v1.providers.clock import Clock
from traust_core.v1.services.operations import OpsService, SpendService

from traust_engine.ops.pack import AssetSpec, Pack, Quota

log = logging.getLogger(__name__)

BUDGET_REASON = "budget-over"
NOT_IN_PACK_REASON = "asset-not-in-pack"


class AdmissionReport(Model):
    admitted: int = 0
    awaiting_approval: int = 0
    withheld: int = 0
    deferred: int = 0


@dataclass
class TokenBucket:
    """Refills `per_hour` tokens an hour, holding at most an hour's worth."""

    per_hour: int
    tokens: float
    at: datetime

    def take(self, now: datetime) -> bool:
        refill = (now - self.at).total_seconds() * self.per_hour / 3600
        self.tokens, self.at = min(self.per_hour, self.tokens + refill), now
        if self.tokens < 1:
            return False
        self.tokens -= 1
        return True


class Admission:
    def __init__(self, pack: Pack, ops: OpsService, spend: SpendService, clock: Clock) -> None:
        self._pack = pack
        self._ops = ops
        self._spend = spend
        self._clock = clock
        self._buckets: dict[str, TokenBucket] = {}

    def admit(self, hosts: Mapping[UUID, str]) -> AdmissionReport:
        """Admit, hold for approval, withhold (budget) or defer (pacing, quota) each planned
        order; `hosts` maps repository ids to forge hosts for the quota buckets."""
        now = self._clock.now()
        planned = every_item(lambda p: self._ops.list(OrderFilter(states=(OrderState.PLANNED,)), p))
        budgets: dict[LaneName, BudgetVerdict] = {}
        committed: Counter[LaneName] = Counter()
        paced: Counter[AssetName] = Counter()
        report = Counter[str]()
        for order in sorted(planned, key=lambda o: (o.priority, o.created_at)):
            asset = AssetName(order.asset)
            spec = self._pack.assets.get(asset)
            pacing, quota = (spec.admission.pacing, spec.admission.quota) if spec else (None, None)
            if spec is None or self._over_budget(order, spec, budgets, committed):
                self._ops.withhold(order.id, BUDGET_REASON if spec else NOT_IN_PACK_REASON)
                report["withheld"] += 1
            elif (pacing and paced[asset] >= pacing.per_tick) or (
                quota and not self._token(quota, order, hosts, now)
            ):
                report["deferred"] += 1
            elif spec.admission.approval:
                self._ops.request_approval(order.id)
                paced[asset] += 1
                report["awaiting_approval"] += 1
            else:
                self._ops.admit(order.id)
                paced[asset] += 1
                report["admitted"] += 1
        if report["withheld"] or report["deferred"]:
            log.warning(
                "admission withheld %d, deferred %d", report["withheld"], report["deferred"]
            )
        return AdmissionReport(**report)

    def _over_budget(
        self,
        order: RunOrder,
        spec: AssetSpec,
        budgets: dict[LaneName, BudgetVerdict],
        committed: Counter[LaneName],
    ) -> bool:
        """The tick's orders share the lane budget in priority order; unknown cost never binds."""
        estimate = spec.admission.estimate_usd
        if order.lane is None or estimate is None:
            return False
        lane = LaneName(order.lane)
        if lane not in budgets:
            budgets[lane] = self._spend.check_budget(lane, Decimal(0))
        base = budgets[lane]
        if base.budget_usd is None or base.enforcement is None:
            return False
        budget = Budget(lane=lane, monthly_usd=base.budget_usd, enforcement=base.enforcement)
        if budget.verdict(base.spent_usd, committed[lane] + estimate).binding:
            return True
        committed[lane] += estimate
        return False

    def _token(
        self, quota: Quota, order: RunOrder, hosts: Mapping[UUID, str], now: datetime
    ) -> bool:
        host = hosts.get(order.repository_id, "") if order.repository_id else ""
        full = TokenBucket(quota.per_hour, quota.per_hour, now)
        return self._buckets.setdefault(quota.bucket(host), full).take(now)
