from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.operations import LaneName

from traust_engine.ops.admission import TokenBucket
from traust_engine.ops.pack import Pack

PACK = Path(__file__).parent / "fixtures" / "packs" / "security-source.yaml"
T0 = datetime(2026, 10, 1, tzinfo=UTC)


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "assets.yaml"
    path.write_text(text)
    return path


def test_load_reads_the_engine_fields_and_ignores_the_runners() -> None:
    pack = Pack.load(PACK)
    repo_state = pack.assets["repo_state"]
    assert (repo_state.partitions, repo_state.trigger.every) == (
        "dynamic:repo",
        timedelta(hours=24),
    )
    quota = repo_state.admission.quota
    assert (
        quota is not None
        and quota.per_hour == 2
        and quota.bucket("github.com") == "forge:github.com"
    )
    assert pack.assets["dependency_graph"].trigger.every == timedelta(days=7)
    assert pack.asset_for_lane(LaneName("diff-scan-quarterly")) == "diff_scan"


def test_topo_order_puts_upstreams_first() -> None:
    order = Pack.load(PACK).topo_order()
    assert order.index("repo_state") < order.index("dependency_graph")
    assert order.index("feeds_cache") < order.index("dependency_graph")
    assert order.index("repo_state") < order.index("diff_scan")


def test_a_lane_no_asset_runs_is_a_config_error() -> None:
    with pytest.raises(ConfigError):
        Pack.load(PACK).asset_for_lane(LaneName("full-audit"))


@pytest.mark.parametrize(
    "assets",
    [
        "a: {deps: [missing]}",
        "a: {deps: [b]}\n  b: {deps: [a]}",
        "a: {trigger: {lanes: [x]}}\n  b: {trigger: {lanes: [x]}}",
        "a: {trigger: {every: soon}}",
        "a: {admission: {quota: {key: k, per_hour: 0}}}",
        "a: {admission: {pacing: {per_tick: 0}}}",
        "a: {trigger: {evry: 24h}}",
        "a: {partitions: repository}",
    ],
    ids=[
        "unknown dep",
        "cycle",
        "shared lane",
        "bad duration",
        "zero quota",
        "zero pacing",
        "misspelt key (schema)",
        "unknown partitioning (schema)",
    ],
)
def test_an_inconsistent_pack_is_a_config_error(tmp_path: Path, assets: str) -> None:
    with pytest.raises(ConfigError):
        Pack.load(_write(tmp_path, f"pack: p\nassets:\n  {assets}\n"))


@pytest.mark.parametrize("route_on", ["missing", "a"], ids=["unknown", "no cadence"])
def test_route_on_must_be_an_asset_with_a_cadence(tmp_path: Path, route_on: str) -> None:
    with pytest.raises(ConfigError):
        Pack.load(_write(tmp_path, f"pack: p\nroute_on: {route_on}\nassets:\n  a: {{}}\n"))


@pytest.mark.parametrize("text", [None, "pack: [unclosed"], ids=["missing file", "bad yaml"])
def test_an_unreadable_pack_is_a_config_error(tmp_path: Path, text: str | None) -> None:
    path = tmp_path / "assets.yaml"
    if text is not None:
        path.write_text(text)
    with pytest.raises(ConfigError):
        Pack.load(path)


def test_a_token_bucket_spends_then_refills_up_to_an_hours_worth() -> None:
    bucket = TokenBucket(per_hour=2, tokens=2, at=T0)
    assert [bucket.take(T0) for _ in range(3)] == [True, True, False]
    assert bucket.take(T0 + timedelta(minutes=29)) is False
    assert bucket.take(T0 + timedelta(minutes=30)) is True
    assert bucket.take(T0 + timedelta(days=1)) is True
    assert bucket.tokens == 1
