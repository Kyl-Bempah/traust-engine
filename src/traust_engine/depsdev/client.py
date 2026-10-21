"""deps.dev dependency resolution: one client, the OSV client's failure rule.

``GET /v3/systems/{system}/packages/{name}/versions/{version}:dependencies``
returns the resolved dependency graph of one package version, "similar to
one produced by installing the package version on a generic 64-bit Linux
system, with no other dependencies present". Available for npm, PyPI, Maven
and Cargo.

**A failed lookup is never an empty graph.** Each answer is a
``Resolution`` whose ``status`` is ``ok`` or ``not-found`` (HTTP 404: the
registry has no such version), or one of the OSV client's failure
statuses: ``unreachable``, ``quota-deferred`` or ``error``.

**Terms.** Use of the API is subject to the Google APIs Terms of Service
(https://developers.google.com/terms), which bind whoever runs it. Data
deps.dev generates, which includes resolved dependency graphs, is licensed
CC-BY 4.0; ``ATTRIBUTION`` is the notice every consumer carries. deps.dev
expressly permits clients to cache data served by the API, hence the
optional on-disk cache.
"""

from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.request
from collections import Counter
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

DEFAULT_BASE_URL = "https://api.deps.dev/v3"
USER_AGENT = "traust-engine-depsdev-client"
LICENSE = "CC-BY-4.0"
ATTRIBUTION = (
    "Resolved dependency data: deps.dev (Google LLC), https://deps.dev, licensed under "
    "CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/); used unmodified as "
    "package/version pairs. API use is subject to the Google APIs Terms of Service."
)
# OSV ecosystem -> deps.dev system
SYSTEMS = {"npm": "NPM", "PyPI": "PYPI", "Maven": "MAVEN", "crates.io": "CARGO"}


def normalize_base_url(url: str | None) -> str:
    """Accept the base or a full ``…/v3/systems/…`` template; return ``…/v3``."""
    base = (url or DEFAULT_BASE_URL).rstrip("/")
    return base.split("/systems/", 1)[0].removesuffix("/systems")


@dataclass
class Resolution:
    status: str
    nodes: list[tuple[str, str, str]] = field(default_factory=list)  # (name, version, relation)
    detail: str = ""
    cached: bool = False

    @property
    def ok(self) -> bool:
        return self.status == "ok"


class _Failure(Exception):
    def __init__(self, status: str, detail: str):
        super().__init__(detail)
        self.status = status


class DepsDevClient:
    def __init__(
        self,
        base_url: str | None = None,
        *,
        timeout: float = 30.0,
        retries: int = 3,
        backoff: float = 2.0,
        workers: int = 4,
        cache_dir: Path | None = None,
        cache_ttl_hours: float = 24.0,
        opener: Callable | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.base_url = normalize_base_url(base_url)
        self.timeout = timeout
        self.retries = max(1, retries)
        self.backoff = backoff
        self.workers = max(1, workers)
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.cache_ttl = cache_ttl_hours * 3600
        self._open = opener or urllib.request.urlopen
        self._sleep = sleep
        self._clock = clock

    # -- transport ---------------------------------------------------------

    def _get(self, url: str) -> dict:
        last: _Failure | None = None
        for attempt in range(self.retries):
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            try:
                with self._open(req, timeout=self.timeout) as resp:
                    raw = resp.read()
                try:
                    doc = json.loads(raw)
                except (json.JSONDecodeError, ValueError) as e:
                    raise _Failure("error", f"unparseable response from {url}: {e}") from None
                if not isinstance(doc, dict):
                    raise _Failure("error", f"unexpected response shape from {url}")
                return doc
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    raise _Failure("not-found", f"HTTP 404 from {url}") from None
                if e.code == 429:
                    last = _Failure("quota-deferred", f"HTTP 429 from {url}")
                elif e.code >= 500:
                    last = _Failure("unreachable", f"HTTP {e.code} from {url}")
                else:
                    raise _Failure("error", f"HTTP {e.code} from {url}") from None
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last = _Failure("unreachable", f"{type(e).__name__} reaching {url}")
            if attempt + 1 < self.retries:
                self._sleep(self.backoff * (attempt + 1))
        assert last is not None
        raise last

    def url(self, ecosystem: str, name: str, version: str) -> str:
        system = SYSTEMS[ecosystem]
        return (
            f"{self.base_url}/systems/{system.lower()}/packages/{quote(name, safe='')}"
            f"/versions/{quote(version, safe='')}:dependencies"
        )

    # -- cache -------------------------------------------------------------

    def _cache_path(self, key: tuple[str, str, str]) -> Path | None:
        if self.cache_dir is None:
            return None
        digest = hashlib.sha256("\x00".join(key).encode()).hexdigest()
        return self.cache_dir / f"{digest}.json"

    def _cached(self, key: tuple[str, str, str]) -> Resolution | None:
        path = self._cache_path(key)
        if path is None:
            return None
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if doc.get("key") != list(key) or self._clock() - doc.get("fetched_at", 0) > self.cache_ttl:
            return None
        nodes = [tuple(n) for n in doc.get("nodes") or []]
        return Resolution(doc.get("status", "error"), nodes, cached=True)

    def _store(self, key: tuple[str, str, str], res: Resolution) -> None:
        path = self._cache_path(key)
        if path is None or res.status not in ("ok", "not-found"):
            return  # failures are never cached
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(
                json.dumps(
                    {
                        "key": list(key),
                        "fetched_at": self._clock(),
                        "status": res.status,
                        "nodes": [list(n) for n in res.nodes],
                    }
                ),
                encoding="utf-8",
            )
            tmp.replace(path)
        except OSError:
            pass  # a cache that cannot be written only costs a refetch

    # -- queries -----------------------------------------------------------

    def dependencies(self, ecosystem: str, name: str, version: str) -> Resolution:
        """The resolved graph of one package version (``SELF`` node excluded)."""
        key = (ecosystem, name, version)
        if ecosystem not in SYSTEMS:
            return Resolution("unsupported", detail=f"deps.dev does not resolve {ecosystem}")
        hit = self._cached(key)
        if hit is not None:
            return hit
        try:
            doc = self._get(self.url(*key))
        except _Failure as f:
            res = Resolution(f.status, detail=str(f))
        else:
            nodes = []
            for node in doc.get("nodes") or []:
                vk = (node or {}).get("versionKey") or {}
                relation = node.get("relation") or ""
                if relation == "SELF" or not vk.get("name") or not vk.get("version"):
                    continue
                nodes.append((vk["name"], vk["version"], relation))
            res = Resolution("ok", sorted(set(nodes)))
        self._store(key, res)
        return res

    def default_version(self, ecosystem: str, name: str) -> Resolution:
        """The version deps.dev marks default (what an install gets today).

        ``nodes`` holds one ``(name, version, "DEFAULT")`` entry when found.
        """
        key = (ecosystem, name, "")
        if ecosystem not in SYSTEMS:
            return Resolution("unsupported", detail=f"deps.dev does not resolve {ecosystem}")
        hit = self._cached(key)
        if hit is not None:
            return hit
        url = (
            f"{self.base_url}/systems/{SYSTEMS[ecosystem].lower()}/packages/{quote(name, safe='')}"
        )
        try:
            doc = self._get(url)
        except _Failure as f:
            res = Resolution(f.status, detail=str(f))
        else:
            default = next(
                (
                    (v.get("versionKey") or {}).get("version")
                    for v in doc.get("versions") or []
                    if isinstance(v, dict) and v.get("isDefault")
                ),
                None,
            )
            res = (
                Resolution("ok", [(name, default, "DEFAULT")])
                if default
                else Resolution("not-found", detail=f"no default version for {name}")
            )
        self._store(key, res)
        return res

    def defaults_many(self, names: Iterable[tuple[str, str]]) -> dict[tuple[str, str], Resolution]:
        unique = sorted(set(names))
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            return dict(
                zip(unique, pool.map(lambda k: self.default_version(*k), unique), strict=True)
            )

    def probe(self, key: tuple[str, str, str]) -> tuple[str, str] | None:
        """One lookup before a run: ``None`` if deps.dev answers (404 counts)."""
        res = self.dependencies(*key)
        if res.status in ("ok", "not-found", "unsupported"):
            return None
        return res.status, res.detail

    def resolve_many(
        self, keys: Iterable[tuple[str, str, str]]
    ) -> tuple[dict[tuple[str, str, str], Resolution], Counter]:
        unique = sorted(set(keys))
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            results = dict(
                zip(unique, pool.map(lambda k: self.dependencies(*k), unique), strict=True)
            )
        return results, Counter(r.status for r in results.values())
