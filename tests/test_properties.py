"""Property-based tests for DepTriage (REQ-6, REQ-7, REQ-8).

REQ-6 [PBT] — threshold exit-code equivalence:
    exit_code_for(findings, threshold) == 1  iff  any finding meets the
    threshold; otherwise 0.

REQ-7 [PBT] — finding completeness:
    rank(findings) is a permutation of findings — no finding is added,
    dropped, or duplicated by the ranker.

REQ-8 [PBT] — no dropped critical/high findings:
    Every critical or high finding present in the input list also appears
    in the ranked output (safety-critical findings are never silently lost).
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from deptriage.models import Finding, Package
from deptriage.ranker import ORDERED_SEVERITIES, rank
from deptriage.report import exit_code_for

# ---------------------------------------------------------------------------
# Shared strategies
# ---------------------------------------------------------------------------

# Valid severity labels (the full set used by the ranker).
_SEVERITIES = list(ORDERED_SEVERITIES)  # critical, high, medium, low, unknown

# A strategy for a single Finding with a controllable severity.  We keep the
# Package fields minimal but valid so the ranker and reporter work without
# touching the filesystem or the network.
_package_st = st.builds(
    Package,
    name=st.text(
        alphabet=st.characters(
            whitelist_categories=("Ll", "Lu", "Nd"),
            whitelist_characters="-_.",
        ),
        min_size=1,
        max_size=30,
    ),
    ecosystem=st.sampled_from(["npm", "PyPI"]),
    version=st.from_regex(r"\d+\.\d+\.\d+", fullmatch=True),
    original_spec=st.just("1.0.0"),
    source_file=st.just("package.json"),
)

_finding_st = st.builds(
    Finding,
    package=_package_st,
    osv_id=st.from_regex(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", fullmatch=True),
    aliases=st.just([]),
    summary=st.text(max_size=80),
    severity=st.sampled_from(_SEVERITIES),
    score=st.one_of(st.none(), st.floats(min_value=0.0, max_value=10.0, allow_nan=False)),
    score_type=st.one_of(st.none(), st.just("CVSS_V3"), st.just("CVSS_V2")),
    fixed_version=st.one_of(st.none(), st.from_regex(r"\d+\.\d+\.\d+", fullmatch=True)),
)

_findings_list_st = st.lists(_finding_st, max_size=20)

# A strategy for one of the four threshold levels accepted by the CLI.
_threshold_st = st.sampled_from(["critical", "high", "medium", "low"])


# ---------------------------------------------------------------------------
# REQ-6 [PBT] — threshold exit-code equivalence
# ---------------------------------------------------------------------------

@given(findings=_findings_list_st, threshold=_threshold_st)
@settings(max_examples=300)
def test_exit_code_equivalence(findings: list[Finding], threshold: str) -> None:
    """exit_code_for returns 1 iff at least one finding meets the threshold.

    This is a bidirectional equivalence:
    - If any finding meets the threshold  →  exit code MUST be 1.
    - If no finding meets the threshold   →  exit code MUST be 0.
    """
    from deptriage.ranker import meets_threshold

    any_meets = any(meets_threshold(f, threshold) for f in findings)
    code = exit_code_for(findings, threshold)

    if any_meets:
        assert code == 1, (
            f"Expected exit code 1 when a finding meets threshold={threshold!r}, got {code}."
        )
    else:
        assert code == 0, (
            f"Expected exit code 0 when no finding meets threshold={threshold!r}, got {code}."
        )


# ---------------------------------------------------------------------------
# REQ-7 [PBT] — finding completeness (rank is a pure permutation)
# ---------------------------------------------------------------------------

@given(findings=_findings_list_st)
@settings(max_examples=300)
def test_rank_is_a_permutation(findings: list[Finding]) -> None:
    """rank() returns exactly the same findings — no additions, drops, or duplicates.

    Checked via identity (id) so that two Finding objects with identical
    field values are still distinguished.
    """
    ranked = rank(findings)

    # Same length.
    assert len(ranked) == len(findings), (
        f"rank() changed the count: {len(findings)} in → {len(ranked)} out."
    )

    # Same objects by identity — nothing was invented or silently removed.
    assert sorted(id(f) for f in ranked) == sorted(id(f) for f in findings), (
        "rank() dropped or duplicated at least one Finding object."
    )


# ---------------------------------------------------------------------------
# REQ-8 [PBT] — no dropped critical/high findings
# ---------------------------------------------------------------------------

@given(findings=_findings_list_st)
@settings(max_examples=300)
def test_no_critical_high_findings_dropped(findings: list[Finding]) -> None:
    """Every critical or high finding in the input is present in the ranked output.

    This is a safety guarantee: high-risk findings must never be silently
    lost by the ranking step, regardless of what other findings are present.
    """
    high_risk_in = {id(f) for f in findings if f.severity in ("critical", "high")}
    ranked = rank(findings)
    high_risk_out = {id(f) for f in ranked if f.severity in ("critical", "high")}

    dropped = high_risk_in - high_risk_out
    assert not dropped, (
        f"{len(dropped)} critical/high finding(s) were dropped by rank()."
    )
