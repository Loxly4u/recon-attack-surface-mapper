"""
Attack surface reporting module.

Generates a natural-language summary for each high-priority asset and an
overall attack surface report so a security team can understand "what's
exposed and what to fix first" without manually reading raw recon JSON.

Report generation backend is pluggable, mirroring the pattern used in the
sibling soc-alert-triage-engine project's summarization.py:
  - If an OpenAI-compatible API key is configured (OPENAI_API_KEY env var),
    an LLM is used to produce a richer narrative.
  - Otherwise, a deterministic offline template-based generator is used,
    so the tool works fully offline with zero external dependencies/cost.

This module performs NO network scanning. Any LLM call (opt-in only) sends
only the already-ingested sample recon findings as text context for
narrative generation.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from recon_mapper.prioritization import ScoredAsset

_ACTION_BY_SEVERITY = {
    "high": "Remediate immediately: close/restrict the exposed service, patch or upgrade affected software, and verify no exploitation has occurred.",
    "medium": "Schedule remediation in the current sprint. Validate whether exposure is intentional and apply compensating controls if not.",
    "low": "Track for routine hardening. No urgent action required unless additional findings emerge.",
}


@dataclass
class AssetSummary:
    asset_id: str
    hostname: str
    score: int
    severity: str
    narrative: str
    recommended_action: str
    finding_descriptions: list[str] = field(default_factory=list)


@dataclass
class AttackSurfaceReport:
    organization: str
    total_assets: int
    high_count: int
    medium_count: int
    low_count: int
    overview: str
    asset_summaries: list[AssetSummary] = field(default_factory=list)


def _offline_asset_summary(scored: ScoredAsset) -> AssetSummary:
    """Deterministic, template-based per-asset summary (no external calls)."""
    asset = scored.asset
    finding_descs = [f.description for f in scored.findings]

    if not finding_descs:
        narrative = (
            f"'{asset.hostname}' was observed with no significant risk indicators "
            f"in the current recon data. It appears to be routine infrastructure."
        )
    else:
        top_findings = finding_descs[:4]
        extra = len(finding_descs) - len(top_findings)
        findings_text = "; ".join(top_findings)
        extra_text = f" (+{extra} more finding(s))" if extra > 0 else ""
        ip_text = ", ".join(asset.ip_addresses) if asset.ip_addresses else "no recorded IP"
        narrative = (
            f"'{asset.hostname}' ({ip_text}) was flagged {scored.severity.upper()} risk "
            f"(score {scored.score}). Key findings: {findings_text}{extra_text}."
        )

    return AssetSummary(
        asset_id=asset.asset_id,
        hostname=asset.hostname,
        score=scored.score,
        severity=scored.severity,
        narrative=narrative,
        recommended_action=_ACTION_BY_SEVERITY.get(scored.severity, "Review during routine triage."),
        finding_descriptions=finding_descs,
    )


def _llm_asset_summary(scored: ScoredAsset) -> AssetSummary:
    """
    LLM-backed per-asset summary. Requires `openai` package and
    OPENAI_API_KEY.

    Falls back to the offline summarizer if the call fails for any reason
    (missing package, network error, invalid key) so the pipeline never
    hard-fails due to reporting issues.
    """
    try:
        from openai import OpenAI  # type: ignore

        client = OpenAI()
        asset = scored.asset
        findings_text = "\n".join(f"- {f.description}" for f in scored.findings) or "- No notable findings"
        prompt = (
            "You are a security analyst assistant reviewing PRE-COLLECTED, "
            "SAMPLE reconnaissance data (not a live scan). Summarize the "
            "exposure of the following asset into a concise 2-3 sentence "
            "narrative a security team can act on, then suggest one "
            "recommended next action.\n\n"
            f"Hostname: {asset.hostname}\n"
            f"IPs: {', '.join(asset.ip_addresses) or 'n/a'}\n"
            f"Risk score: {scored.score} ({scored.severity})\n"
            f"Findings:\n{findings_text}"
        )
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=300,
        )
        content = response.choices[0].message.content or ""
        narrative = content.strip()
        offline = _offline_asset_summary(scored)
        return AssetSummary(
            asset_id=asset.asset_id,
            hostname=asset.hostname,
            score=scored.score,
            severity=scored.severity,
            narrative=narrative or offline.narrative,
            recommended_action=offline.recommended_action,
            finding_descriptions=offline.finding_descriptions,
        )
    except Exception:
        return _offline_asset_summary(scored)


def summarize_asset(scored: ScoredAsset, use_llm: bool | None = None) -> AssetSummary:
    """
    Summarize a single scored asset.

    Args:
        scored: the scored asset to summarize.
        use_llm: force LLM usage on/off. If None, auto-detects based on
            whether OPENAI_API_KEY is set in the environment.
    """
    if use_llm is None:
        use_llm = bool(os.environ.get("OPENAI_API_KEY"))

    if use_llm:
        return _llm_asset_summary(scored)
    return _offline_asset_summary(scored)


def _build_overview(organization: str, scored_assets: list[ScoredAsset]) -> str:
    total = len(scored_assets)
    high = sum(1 for s in scored_assets if s.severity == "high")
    medium = sum(1 for s in scored_assets if s.severity == "medium")
    low = sum(1 for s in scored_assets if s.severity == "low")

    if total == 0:
        return f"No assets were found in the recon data for {organization}."

    top_names = ", ".join(s.hostname for s in scored_assets[:3] if s.severity == "high")
    high_text = (
        f" The highest-priority assets requiring immediate attention are: {top_names}."
        if top_names
        else ""
    )

    return (
        f"Attack surface analysis for {organization} identified {total} asset(s) from "
        f"pre-collected recon data: {high} high-risk, {medium} medium-risk, and {low} "
        f"low-risk.{high_text} This report is based on offline analysis of sample/synthetic "
        f"data only; no live scanning was performed."
    )


def generate_report(
    organization: str,
    scored_assets: list[ScoredAsset],
    use_llm: bool | None = None,
) -> AttackSurfaceReport:
    """Generate the full attack surface report from a list of scored assets."""
    summaries = [summarize_asset(sa, use_llm=use_llm) for sa in scored_assets]
    high = sum(1 for s in scored_assets if s.severity == "high")
    medium = sum(1 for s in scored_assets if s.severity == "medium")
    low = sum(1 for s in scored_assets if s.severity == "low")

    return AttackSurfaceReport(
        organization=organization,
        total_assets=len(scored_assets),
        high_count=high,
        medium_count=medium,
        low_count=low,
        overview=_build_overview(organization, scored_assets),
        asset_summaries=summaries,
    )
