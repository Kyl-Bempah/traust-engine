"""Version gates across the 2026-09-10 reset, and review-surface cross-checks."""

import pytest

from traust_engine.reporting import validate as V

SURFACES = V._review_surfaces()


def meta(hv, date, *, profile="code", original=None):
    m = {"date": date, "audit_profile": profile, "additional": {"harness_version": hv}}
    if original:
        m["additional"]["cumulative"] = {"original_report_date": original}
    return m


class TestGate:
    def test_pre_reset_compares_in_the_old_numbering(self):
        assert V._gate(meta("0.186.2-abc", "2026-07-21"), legacy=(0, 60, 1))
        assert not V._gate(meta("0.14.0", "2026-06-01"), legacy=(0, 15, 0))

    def test_post_reset_reports_meet_every_legacy_gate(self):
        # 0.5.0 is below 0.60.1 numerically, but every post-reset release
        # includes everything the old numbering gated.
        assert V._gate(meta("0.5.0", "2026-10-01"), legacy=(0, 60, 1))

    def test_current_gates_compare_in_the_new_numbering(self):
        assert V._gate(meta("0.20.0", "2026-10-20"), current=(0, 20, 0))
        assert not V._gate(meta("0.19.1", "2026-10-20"), current=(0, 20, 0))

    def test_a_pre_reset_report_never_meets_a_current_gate(self):
        assert not V._gate(meta("0.186.2", "2026-07-21"), current=(0, 20, 0))

    def test_cumulative_reports_use_the_audit_date(self):
        # build_cumulative re-stamps metadata.date with its build date.
        rebuilt = meta("0.186.2", "2026-10-15", original="2026-07-21")
        assert not V._gate(rebuilt, current=(0, 20, 0))
        early = meta("0.4.2", "2026-10-15", original="2026-05-26")
        assert not V._gate(early, legacy=(0, 12, 0))

    def test_no_harness_version_is_never_gated(self):
        assert not V._gate({"date": "2026-10-20"}, legacy=(0, 1, 0))


def coverage(**overrides):
    record = {s: {"status": "negative"} for s in SURFACES}
    record.update(overrides)
    return record


def report(record=None, *, m=None, findings=(), negatives=None, gaps=()):
    r = {
        "metadata": m or meta("0.20.0", "2026-10-20"),
        "findings": [{"id": fid} for fid in findings],
        "negative_results": negatives
        if negatives is not None
        else [{"area": s, "result": "examined"} for s in SURFACES],
    }
    if gaps:
        r["metadata"]["additional"]["coverage_gaps"] = list(gaps)
    if record is not None:
        r["review_surface_coverage"] = record
    return r


def errors(r):
    result = V.ValidationResult("x")
    V._cross_validate_review_surfaces(r, result)
    return result.errors


class TestRequired:
    def test_required_from_the_shipping_release(self):
        assert any("required" in e for e in errors(report()))

    @pytest.mark.parametrize(
        "m",
        [
            meta("0.19.1", "2026-10-20"),  # post-reset, before the release
            meta("0.186.2", "2026-07-21"),  # pre-reset numbering
            meta("0.186.2", "2026-10-15", original="2026-07-21"),  # cumulative rebuild
            meta("0.20.0", "2026-10-20", profile="container"),  # other profiles
        ],
    )
    def test_not_required_elsewhere(self, m):
        assert errors(report(m=m)) == []


class TestCrossChecks:
    def test_a_consistent_record_passes(self):
        record = coverage(
            **{
                "credential-acceptance": {"status": "finding", "finding_ids": ["R-abc1234-001"]},
                "stored-content-integrity": {"status": "not_applicable", "note": "no store"},
                "outbound-fetch": {"status": "not_assessed", "note": "scoped"},
            }
        )
        gaps = [{"tool": "review-surfaces", "system": "outbound-fetch", "reason": "scoped"}]
        assert errors(report(record, findings=["R-abc1234-001"], gaps=gaps)) == []

    def test_finding_ids_must_exist(self):
        record = coverage(**{"scope-enforcement": {"status": "finding", "finding_ids": ["NOPE"]}})
        assert any("'NOPE'" in e for e in errors(report(record)))

    def test_negative_needs_a_negative_result_for_the_surface(self):
        negatives = [{"area": s, "result": "x"} for s in SURFACES if s != "security-flags"]
        assert any("security-flags" in e for e in errors(report(coverage(), negatives=negatives)))

    def test_a_qualified_area_matches(self):
        negatives = [{"area": f"{s} (detail)", "result": "x"} for s in SURFACES]
        assert errors(report(coverage(), negatives=negatives)) == []

    def test_a_prefix_lookalike_does_not_match(self):
        negatives = [{"area": s + "s", "result": "x"} for s in SURFACES]
        assert len(errors(report(coverage(), negatives=negatives))) == len(SURFACES)

    def test_not_assessed_needs_a_coverage_gap(self):
        record = coverage(**{"outbound-fetch": {"status": "not_assessed", "note": "scoped"}})
        assert any("coverage_gaps" in e for e in errors(report(record)))
