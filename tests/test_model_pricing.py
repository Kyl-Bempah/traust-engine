"""Per-model cache-read multipliers and long-prompt pricing (traust-contracts 0.59.0)."""

import json

import pytest
from traust_contracts import ModelRegistry

from traust_engine.metrics import attribute_spend, collect_spend
from traust_engine.registry.models import cost_usd, long_prompt_thresholds


def _reg():
    return ModelRegistry.model_validate(
        {
            "version": 1,
            "updated": "2026-10-16",
            "tiers": {"haiku-class": {}, "opus-class": {}},
            "providers": {
                "anthropic": {
                    "data_handling": "test",
                    "models": {
                        "std": {
                            "tier": "opus-class",
                            "price_per_mtok_in": 5.0,
                            "price_per_mtok_out": 25.0,
                        },
                        "cheap-cache": {
                            "tier": "opus-class",
                            "price_per_mtok_in": 4.0,
                            "price_per_mtok_out": 20.0,
                            "cache_read_multiplier": 0.05,
                        },
                        "tiered": {
                            "tier": "haiku-class",
                            "price_per_mtok_in": 0.1,
                            "price_per_mtok_out": 0.5,
                            "long_prompt": {
                                "above_tokens": 100_000,
                                "price_per_mtok_in": 0.5,
                                "price_per_mtok_out": 2.5,
                            },
                        },
                    },
                }
            },
            "roles": {},
        }
    )


M = 1_000_000


def test_the_standard_cache_rate_is_unchanged():
    # 1M in + 1M out + 1M cache read at 0.1x + 1M cache write at 1.25x
    assert cost_usd(_reg(), "std", M, M, M, M) == 5 + 25 + 0.5 + 6.25


def test_a_model_cache_multiplier_applies():
    assert cost_usd(_reg(), "cheap-cache", 0, 0, M, 0) == pytest.approx(4 * 0.05)


def test_long_prompt_tokens_take_the_long_rates():
    lp = {"tokens_in": M, "tokens_out": M, "cache_read": M, "cache_creation": 0}
    # the long part at 0.5/2.5 (cache read 0.1x of 0.5); the remaining 1M in at 0.1
    assert cost_usd(_reg(), "tiered", 2 * M, M, M, 0, lp) == pytest.approx(0.1 + 0.5 + 2.5 + 0.05)


def test_without_a_long_prompt_block_everything_is_base():
    assert cost_usd(_reg(), "tiered", M, M) == pytest.approx(0.6)


def test_thresholds_list_only_tiered_models():
    assert long_prompt_thresholds(_reg()) == {"tiered": 100_000}


def _usage(i, o=10, r=0, w=0):
    return {
        "input_tokens": i,
        "output_tokens": o,
        "cache_read_input_tokens": r,
        "cache_creation_input_tokens": w,
    }


def test_each_request_is_judged_on_its_own():
    a = {k: 0 for k in collect_spend.TOKEN_KEYS}
    collect_spend.add_usage(a, _usage(60_000, r=50_000), 100_000)  # prompt 110k: long
    collect_spend.add_usage(a, _usage(90_000), 100_000)  # prompt 90k: base
    assert a["input_tokens"] == 150_000
    assert a["long_prompt"] == {
        "tokens_in": 60_000,
        "tokens_out": 10,
        "cache_read": 50_000,
        "cache_creation": 0,
    }


def test_no_threshold_records_no_long_prompt():
    a = {k: 0 for k in collect_spend.TOKEN_KEYS}
    collect_spend.add_usage(a, _usage(500_000), None)
    assert "long_prompt" not in a


def _transcript(tmp_path, rows):
    d = tmp_path / "proj"
    d.mkdir()
    with (d / "s1.jsonl").open("w") as fh:
        for model, usage in rows:
            fh.write(
                json.dumps(
                    {
                        "timestamp": "2026-10-15T10:00:00Z",
                        "message": {"model": model, "usage": usage},
                    }
                )
                + "\n"
            )
    return d


def test_both_collectors_carry_the_split_into_rows(tmp_path):
    d = _transcript(tmp_path, [("tiered", _usage(150_000)), ("tiered", _usage(1_000))])
    th = long_prompt_thresholds(_reg())
    sessions = collect_spend.collect([d], None, th)["2026-10-15"]["tiered"]
    row = collect_spend._row("tiered", sessions)
    assert row["long_prompt"]["tokens_in"] == 150_000 and row["tokens_in"] == 151_000
    attributed = attribute_spend.collect_attributed([d], valid=set(), thresholds=th)
    a = attributed["2026-10-15"][attribute_spend.UNATTRIBUTED]["tiered"]
    assert a["long_prompt"]["tokens_in"] == 150_000
    # priced from the row exactly as the reports re-derive it
    usd = cost_usd(
        _reg(),
        "tiered",
        row["tokens_in"],
        row["tokens_out"],
        row["cache_read"],
        row["cache_creation"],
        long_prompt=row.get("long_prompt"),
    )
    # cost_usd rounds to 4 decimal places
    assert usd == pytest.approx(
        150_000 / M * 0.5 + 10 / M * 2.5 + 1_000 / M * 0.1 + 10 / M * 0.5, abs=1e-4
    )


def test_the_engine_facade_passes_long_prompt_through():
    from types import SimpleNamespace

    from traust_engine.registry.ops import ModelsOps

    ops = ModelsOps.__new__(ModelsOps)
    ops._ctx = SimpleNamespace(model_registry=_reg())
    lp = {"tokens_in": M, "tokens_out": 0, "cache_read": 0, "cache_creation": 0}
    assert ops.cost_usd("tiered", M, 0, long_prompt=lp) == pytest.approx(0.5)
    assert ops.long_prompt_thresholds() == {"tiered": 100_000}
