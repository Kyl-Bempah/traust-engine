"""The loop over real core services on SQLite: a first tick from empty through routing,
cadence, budget, approval, pacing and the reaper."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
import yaml
from traust_core.v1.context import Config, Context
from traust_core.v1.context.context import Services
from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.common import every_item
from traust_core.v1.models.operations import (
    JobResult,
    OrderFilter,
    OrderRequest,
    OrderState,
    Route,
    RunOrder,
    WorkerId,
)
from traust_core.v1.models.values import HttpsRepoUrl

from traust_engine.controller import ENGINE, Controller
from traust_engine.loop import EngineLoop
from traust_engine.pack import Pack

PACK = Path(__file__).parent / "fixtures" / "packs" / "security-source.yaml"
T0 = datetime(2026, 10, 1, 6, tzinfo=UTC)
WORKER = WorkerId("runner-1")
LEASE = timedelta(minutes=5)
SUCCEEDED = JobResult.succeeded()


class Clock:
    def __init__(self) -> None:
        self.at = T0

    def now(self) -> datetime:
        return self.at


class LaneRouter:
    """Routes every repository to diff-scan except those in `skip`."""

    def __init__(self, skip: frozenset[UUID] = frozenset()) -> None:
        self.skip = skip
        self.seen: list[UUID] = []

    def route(self, state: UUID, events: object, refusals: object) -> Route:
        self.seen.append(state)
        lane = None if state in self.skip else "diff-scan"
        return Route(lane=lane, priority=1, reason="rule-4")  # type: ignore[arg-type]


def _context(tmp_path: Path, clock: Clock, **config: Any) -> Context:
    return Context(Config(home=tmp_path / "home", **config), clock=clock)


def _repositories(services: Services, count: int, host: str = "github.com") -> list[UUID]:
    urls = [HttpsRepoUrl.parse(f"https://{host}/example/r{i}", [host]) for i in range(count)]
    return [services.portfolio.register_repository(u, public=True).id for u in urls]  # type: ignore[misc]


def _orders(services: Services, *states: OrderState) -> list[RunOrder]:
    return list(every_item(lambda p: services.ops.list(OrderFilter(states=states), p)))


def _by_asset(orders: list[RunOrder]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for o in orders:
        counts[o.asset] = counts.get(o.asset, 0) + 1
    return counts


def _drain(services: Services, result: JobResult = SUCCEEDED) -> list[RunOrder]:
    """A runner claims and completes every queued order."""
    done = []
    while (order := services.ops.claim(WORKER, LEASE)) is not None:
        done.append(services.ops.complete(order.id, WORKER, result))  # type: ignore[arg-type]
    return done


def _pack(tmp_path: Path, **changes: dict[str, Any]) -> Pack:
    raw = yaml.safe_load(PACK.read_text())
    for asset, fields in changes.items():
        raw["assets"].setdefault(asset, {}).update(fields)
    path = tmp_path / "assets.yaml"
    path.write_text(yaml.safe_dump(raw))
    return Pack.load(path)


def test_a_first_tick_from_empty_queues_the_source_assets(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repos = _repositories(services, 3)
    report = EngineLoop(services, clock, Pack.load(PACK)).run_once()

    assert report.tick.planned == 4  # feeds_cache + repo_state x3
    assert report.tick.stale == {"dependency_graph": 3}
    assert (report.admission.admitted, report.admission.deferred) == (3, 1)  # quota 2/h
    queued = _orders(services, OrderState.QUEUED)
    assert _by_asset(queued) == {"feeds_cache": 1, "repo_state": 2}
    assert all(o.requested_by == ENGINE.ref and o.lane is None for o in queued)
    (waiting,) = _orders(services, OrderState.PLANNED)
    assert waiting.asset == "repo_state" and waiting.repository_id in repos


def test_a_second_tick_plans_nothing_already_open(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    _repositories(services, 3)
    loop = EngineLoop(services, clock, Pack.load(PACK))
    loop.run_once()
    again = loop.run_once()
    assert again.tick.planned == 0
    assert (again.admission.admitted, again.admission.deferred) == (0, 1)


def test_quota_refills_and_admits_the_deferred_order(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    _repositories(services, 3)
    loop = EngineLoop(services, clock, Pack.load(PACK))
    loop.run_once()
    clock.at += timedelta(minutes=30)
    assert loop.run_once().admission.admitted == 1
    assert _orders(services, OrderState.PLANNED) == []


def test_quota_is_per_forge_host(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    _repositories(services, 2, "github.com")
    _repositories(services, 2, "gitlab.com")
    report = EngineLoop(services, clock, Pack.load(PACK)).run_once()
    assert report.admission.deferred == 0


def test_a_materialized_source_unblocks_downstream_and_routes_once(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repos = _repositories(services, 2)
    router = LaneRouter()
    loop = EngineLoop(services, clock, Pack.load(PACK), router, state_of=lambda r: r)
    loop.run_once()
    clock.at += timedelta(minutes=10)
    _drain(services)

    report = loop.run_once()
    assert report.tick.routed == 2 and sorted(router.seen) == sorted(repos)
    assert report.tick.stale == {}
    queued = _orders(services, OrderState.QUEUED)
    assert _by_asset(queued) == {"diff_scan": 2, "dependency_graph": 2}
    scans = [o for o in queued if o.asset == "diff_scan"]
    assert all((o.lane, o.rule, o.priority) == ("diff-scan", "rule-4", 1) for o in scans)

    router.seen.clear()
    assert loop.run_once().tick.routed == 0  # nothing new materialized since the last tick


def test_a_repository_the_router_leaves_alone_gets_no_routed_order(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    quiet, busy = _repositories(services, 2)
    loop = EngineLoop(services, clock, Pack.load(PACK), LaneRouter(frozenset({quiet})), lambda r: r)
    loop.run_once()
    clock.at += timedelta(minutes=10)
    _drain(services)
    loop.run_once()
    scans = [o for o in _orders(services, OrderState.QUEUED) if o.asset == "diff_scan"]
    assert [o.repository_id for o in scans] == [busy]


def test_a_repository_without_routing_state_is_counted_not_routed(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    _repositories(services, 1)

    def missing(repository_id: UUID) -> UUID:
        raise NotFoundError(f"no forge observation for {repository_id}")

    loop = EngineLoop(services, clock, Pack.load(PACK), LaneRouter(), missing)
    loop.run_once()
    clock.at += timedelta(minutes=10)
    _drain(services)
    report = loop.run_once()
    assert (report.tick.routed, report.tick.unrouted) == (0, 1)


def test_cadence_makes_a_source_due_again(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    _repositories(services, 1)
    loop = EngineLoop(services, clock, Pack.load(PACK))
    loop.run_once()
    _drain(services)
    clock.at += timedelta(hours=23)
    assert _by_asset(_orders(services, OrderState.PLANNED)) == {}
    assert loop.run_once().tick.planned == 1  # dependency_graph, now that its deps are fresh
    clock.at += timedelta(hours=2)
    _drain(services)
    assert loop.run_once().tick.planned == 2  # feeds_cache and repo_state, a day on


def test_a_failed_run_waits_out_the_cadence(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    _repositories(services, 1)
    loop = EngineLoop(services, clock, Pack.load(PACK))
    loop.run_once()
    _drain(services, JobResult.failed("runner-crashed"))
    clock.at += timedelta(hours=1)
    report = loop.run_once()
    assert report.tick.planned == 0
    assert report.tick.stale == {"dependency_graph": 1}


def test_the_reaper_requeues_expired_leases(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    loop = EngineLoop(services, clock, Pack.load(PACK))
    loop.run_once()
    assert services.ops.claim(WORKER, LEASE) is not None
    clock.at += LEASE + timedelta(seconds=1)
    assert loop.run_once().requeued == 1


@pytest.mark.parametrize(
    ("enforcement", "withheld"), [("advisory", 1), ("observe", 0)], ids=["binding", "observe"]
)
def test_the_lane_budget_cuts_the_lowest_priority_routed_work(
    tmp_path: Path, enforcement: str, withheld: int
) -> None:
    clock = Clock()
    budget = {"lane": "diff-scan", "monthly_usd": "3", "enforcement": enforcement}
    services = _context(tmp_path, clock, budgets=[budget]).services()
    first, second = _repositories(services, 2)
    services.ops.plan(
        OrderRequest(asset="diff_scan", priority=1, repository_id=first, lane="diff-scan"), ENGINE
    )
    services.ops.plan(
        OrderRequest(asset="diff_scan", priority=9, repository_id=second, lane="diff-scan"), ENGINE
    )
    report = EngineLoop(services, clock, Pack.load(PACK)).run_once()
    assert report.admission.withheld == withheld
    if withheld:
        (cut,) = _orders(services, OrderState.WITHHELD)
        assert (cut.repository_id, cut.reason) == (second, "budget-over")


def test_unknown_cost_is_never_withheld(tmp_path: Path) -> None:
    clock = Clock()
    budget = {"lane": "diff-scan", "monthly_usd": "0", "enforcement": "enforced"}
    services = _context(tmp_path, clock, budgets=[budget]).services()
    (repo,) = _repositories(services, 1)
    services.ops.plan(
        OrderRequest(asset="diff_scan", priority=1, repository_id=repo, lane="diff-scan"), ENGINE
    )
    pack = _pack(tmp_path, diff_scan={"estimate_usd": None})
    assert EngineLoop(services, clock, pack).run_once().admission.withheld == 0


def test_a_human_gated_asset_waits_for_approval(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    report = EngineLoop(services, clock, _pack(tmp_path, feeds_cache={"approval": True})).run_once()
    assert report.admission.awaiting_approval == 1
    (held,) = _orders(services, OrderState.AWAITING_APPROVAL)
    assert held.asset == "feeds_cache"


def test_pacing_spreads_an_asset_across_ticks(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    _repositories(services, 3)
    pack = _pack(tmp_path, repo_state={"quota": None, "per_tick": 1})
    loop = EngineLoop(services, clock, pack)
    assert loop.run_once().admission.deferred == 2
    assert loop.run_once().admission.deferred == 1


def test_a_planned_order_for_an_asset_the_pack_dropped_is_withheld(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    services.ops.plan(OrderRequest(asset="retired_asset", priority=1), ENGINE)
    report = EngineLoop(services, clock, Pack.load(PACK)).run_once()
    assert report.admission.withheld == 1
    (gone,) = _orders(services, OrderState.WITHHELD)
    assert gone.reason == "asset-not-in-pack"


def test_a_router_needs_its_state_reader(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    with pytest.raises(ValueError):
        Controller(Pack.load(PACK), services.ops, clock, router=LaneRouter())
