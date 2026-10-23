"""A workload pack's asset graph: `assets.yaml`, checked against contracts' `config/v1/pack`."""

from __future__ import annotations

import re
from datetime import timedelta
from decimal import Decimal
from graphlib import CycleError, TopologicalSorter
from pathlib import Path
from typing import Annotated, Literal

import pydantic
import yaml
from traust_core.v1 import contracts
from traust_core.v1.errors import ConfigError, DocumentError
from traust_core.v1.models.base import Dto
from traust_core.v1.models.operations import AssetName, LaneName

_DURATION = re.compile(r"^(\d+)([mhd])$")
_UNITS = {"m": "minutes", "h": "hours", "d": "days"}


def _duration(value: object) -> object:
    if isinstance(value, str) and (m := _DURATION.match(value)):
        return timedelta(**{_UNITS[m[2]]: int(m[1])})
    return value


Duration = Annotated[timedelta, pydantic.BeforeValidator(_duration)]


class Trigger(Dto):
    every: Duration | None = None
    lanes: tuple[LaneName, ...] = ()


class Freshness(Dto):
    warn: Duration | None = None
    fail: Duration | None = None


class Pacing(Dto):
    per_tick: int


class Quota(Dto):
    """A token bucket the engine keeps in memory; `{host}` in the key is the forge host."""

    key: str
    per_hour: int

    def bucket(self, host: str) -> str:
        return self.key.replace("{host}", host)


class Admission(Dto):
    approval: str | None = None
    estimate_usd: Decimal | None = None
    pacing: Pacing | None = None
    quota: Quota | None = None


# Dto: runner fields (run, params, runner, model, ...) are in the schema but not read here.
class AssetSpec(Dto):
    partitions: Literal["dynamic:repo"] | None = None
    deps: tuple[AssetName, ...] = ()
    priority: int = 100
    trigger: Trigger = Trigger()
    freshness: Freshness = Freshness()
    admission: Admission = Admission()


class Pack(Dto):
    pack: str
    route_on: AssetName | None = None
    assets: dict[AssetName, AssetSpec]

    @pydantic.model_validator(mode="after")
    def _graph(self) -> Pack:
        names = set(self.assets)
        if unknown := {d for a in self.assets.values() for d in a.deps} - names:
            raise ValueError(f"deps name unknown assets: {sorted(unknown)}")
        lanes = [lane for a in self.assets.values() for lane in a.trigger.lanes]
        if len(lanes) != len(set(lanes)):
            raise ValueError(f"a lane belongs to one asset: {sorted(lanes)}")
        if self.route_on is not None and (
            self.route_on not in names or self.assets[self.route_on].trigger.every is None
        ):
            raise ValueError(f"route_on {self.route_on!r} must be an asset with trigger.every")
        try:
            self.topo_order()
        except CycleError as e:
            raise ValueError(f"asset deps form a cycle: {e.args[1]}") from e
        return self

    def topo_order(self) -> list[AssetName]:
        return list(TopologicalSorter({n: a.deps for n, a in self.assets.items()}).static_order())

    def asset_for_lane(self, lane: LaneName) -> AssetName:
        found = next((n for n, a in self.assets.items() if lane in a.trigger.lanes), None)
        if found is None:
            raise ConfigError(f"pack {self.pack}: no asset runs lane {lane!r}")
        return found

    @classmethod
    def load(cls, path: Path) -> Pack:
        try:
            raw = yaml.safe_load(path.read_text())
            contracts.validate_config("pack", raw)
            return cls.model_validate(raw)
        except (OSError, yaml.YAMLError, DocumentError, pydantic.ValidationError) as e:
            raise ConfigError(f"{path}: {e}") from e
