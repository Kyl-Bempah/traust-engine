"""A workload pack's asset graph, as the engine reads it from the pack's `assets.yaml`."""

from __future__ import annotations

import re
from datetime import timedelta
from decimal import Decimal
from enum import StrEnum
from graphlib import CycleError, TopologicalSorter
from pathlib import Path
from typing import Annotated

import pydantic
import yaml
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.base import Dto
from traust_core.v1.models.operations import AssetName, LaneName

_DURATION = re.compile(r"^(\d+)([mhd])$")
_UNITS = {"m": "minutes", "h": "hours", "d": "days"}


def _duration(value: object) -> object:
    if isinstance(value, str) and (m := _DURATION.match(value)):
        return timedelta(**{_UNITS[m[2]]: int(m[1])})
    return value


Duration = Annotated[timedelta, pydantic.BeforeValidator(_duration)]


class Partitions(StrEnum):
    REPOSITORY = "repository"


class Quota(Dto):
    """Forge calls allowed per host per hour; the bucket lives in the engine, not the database."""

    per_hour: int = pydantic.Field(gt=0)


# Dto: the pack's YAML carries fields for runners and materializers that the engine doesn't read.
class AssetSpec(Dto):
    partitions: Partitions | None = None
    deps: tuple[AssetName, ...] = ()
    every: Duration | None = None
    lanes: tuple[LaneName, ...] = ()
    priority: int = 100
    estimate_usd: Decimal | None = None
    per_tick: int | None = pydantic.Field(default=None, gt=0)
    quota: Quota | None = None
    approval: bool = False


class Pack(Dto):
    pack: str
    route_on: AssetName | None = None
    assets: dict[AssetName, AssetSpec]

    @pydantic.model_validator(mode="after")
    def _graph(self) -> Pack:
        names = set(self.assets)
        if unknown := {d for a in self.assets.values() for d in a.deps} - names:
            raise ValueError(f"deps name unknown assets: {sorted(unknown)}")
        lanes = [lane for a in self.assets.values() for lane in a.lanes]
        if len(lanes) != len(set(lanes)):
            raise ValueError(f"a lane belongs to one asset: {sorted(lanes)}")
        if self.route_on is not None and (
            self.route_on not in names or self.assets[self.route_on].every is None
        ):
            raise ValueError(f"route_on {self.route_on!r} must be an asset with a cadence")
        try:
            self.topo_order()
        except CycleError as e:
            raise ValueError(f"asset deps form a cycle: {e.args[1]}") from e
        return self

    def topo_order(self) -> list[AssetName]:
        return list(TopologicalSorter({n: a.deps for n, a in self.assets.items()}).static_order())

    def asset_for_lane(self, lane: LaneName) -> AssetName:
        found = next((n for n, a in self.assets.items() if lane in a.lanes), None)
        if found is None:
            raise ConfigError(f"pack {self.pack}: no asset runs lane {lane!r}")
        return found

    @classmethod
    def load(cls, path: Path) -> Pack:
        try:
            return cls.model_validate(yaml.safe_load(path.read_text()))
        except (OSError, yaml.YAMLError, pydantic.ValidationError) as e:
            raise ConfigError(f"{path}: {e}") from e
