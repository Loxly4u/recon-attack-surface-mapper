"""Tests for recon_mapper.reporting."""

from __future__ import annotations

import os

import pytest

from recon_mapper.ingestion import Asset, AssetGraph, Service, TlsInfo
from recon_mapper.prioritization import prioritize_assets, score_asset
from recon_mapper.reporting import generate_report, summarize_asset


def _asset(**overrides) -> Asset:
    defaults = dict(
        asset_id="a1",
        hostname="host.example.com",
        ip_addresses=["10.0.0.1"],
        services=[],
        tech_stack=[],
        tls=TlsInfo(enabled=True),
        tags=[],
        source="test",
        notes="",
    )
    defaults.update(overrides)
    return Asset(**defaults)


def test_offline_summary_for_clean_asset_mentions_no_risk():
    asset = _asset(hostname="status.example.com", services=[])
    scored = score_asset(asset)
    summary = summarize_asset(scored, use_llm=False)
    assert "status.example.com" in summary.narrative
    assert summary.severity == "low"


def test_offline_summary_for_risky_asset_includes_findings():
    asset = _asset(
        hostname="rdp.example.com",
        services=[Service(port=3389, service_name="ms-wbt-server")],
        tls=TlsInfo(enabled=False),
    )
    scored = score_asset(asset)
    summary = summarize_asset(scored, use_llm=False)
    assert "rdp.example.com" in summary.narrative
    assert summary.severity == "high"
    assert len(summary.finding_descriptions) > 0
    assert "immediately" in summary.recommended_action.lower()


def test_summary_truncates_findings_list_in_narrative_but_keeps_full_list():
    asset = _asset(
        hostname="multi-risk.example.com",
        services=[
            Service(port=3389, service_name="ms-wbt-server"),
            Service(port=23, service_name="telnet"),
            Service(port=445, service_name="microsoft-ds"),
            Service(port=21, service_name="ftp"),
            Service(port=135, service_name="msrpc"),
        ],
        tls=TlsInfo(enabled=False),
    )
    scored = score_asset(asset)
    summary = summarize_asset(scored, use_llm=False)
    assert len(scored.findings) >= 5
    assert "more finding" in summary.narrative


def test_summarize_asset_defaults_to_offline_when_no_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    asset = _asset(hostname="host.example.com", services=[])
    scored = score_asset(asset)
    summary = summarize_asset(scored, use_llm=None)
    assert summary.hostname == "host.example.com"


def test_summarize_asset_llm_path_falls_back_gracefully_without_openai_pkg(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "fake-key-for-test")
    asset = _asset(hostname="host.example.com", services=[])
    scored = score_asset(asset)
    # Should not raise even if `openai` package is missing or call fails;
    # falls back to offline summary.
    summary = summarize_asset(scored, use_llm=True)
    assert summary.hostname == "host.example.com"
    assert summary.narrative


def test_generate_report_overview_includes_counts():
    assets = [
        _asset(hostname="status.example.com", services=[]),
        _asset(
            hostname="rdp.example.com",
            services=[Service(port=3389, service_name="ms-wbt-server")],
            tls=TlsInfo(enabled=False),
        ),
    ]
    graph = AssetGraph(organization="Acme Test Co", assets=assets)
    scored = prioritize_assets(graph)
    report = generate_report(graph.organization, scored, use_llm=False)
    assert report.organization == "Acme Test Co"
    assert report.total_assets == 2
    assert report.high_count == 1
    assert report.low_count == 1
    assert "Acme Test Co" in report.overview
    assert "rdp.example.com" in report.overview


def test_generate_report_empty_asset_list():
    report = generate_report("Empty Org", [], use_llm=False)
    assert report.total_assets == 0
    assert "No assets" in report.overview


def test_generate_report_asset_summaries_match_input_order():
    assets = [
        _asset(
            hostname="rdp.example.com",
            services=[Service(port=3389, service_name="ms-wbt-server")],
            tls=TlsInfo(enabled=False),
        ),
        _asset(hostname="status.example.com", services=[]),
    ]
    graph = AssetGraph(organization="Order Test", assets=assets)
    scored = prioritize_assets(graph)
    report = generate_report(graph.organization, scored, use_llm=False)
    assert [s.hostname for s in report.asset_summaries] == [sa.hostname for sa in scored]
