"""Tests for recon_mapper.prioritization."""

from __future__ import annotations

from recon_mapper.ingestion import Asset, AssetGraph, Service, TlsInfo
from recon_mapper.prioritization import prioritize_assets, score_asset


def _asset(**overrides) -> Asset:
    defaults = dict(
        asset_id="a1",
        hostname="host.example.com",
        ip_addresses=["10.0.0.1"],
        services=[],
        tech_stack=[],
        tls=TlsInfo(enabled=True, issuer="Let's Encrypt", valid_to="2027-01-01", expired=False, self_signed=False),
        tags=[],
        source="test",
        notes="",
    )
    defaults.update(overrides)
    return Asset(**defaults)


def test_clean_asset_scores_low():
    asset = _asset(
        hostname="www.example.com",
        services=[Service(port=443, service_name="https", product="nginx", version="1.25.3")],
    )
    scored = score_asset(asset)
    assert scored.severity == "low"
    assert scored.score < 15


def test_rdp_exposed_scores_high():
    asset = _asset(
        hostname="rdp-gateway.example.com",
        services=[Service(port=3389, service_name="ms-wbt-server")],
        tls=TlsInfo(enabled=False),
    )
    scored = score_asset(asset)
    assert scored.severity == "high"
    assert any(f.category == "exposed_port" for f in scored.findings)


def test_telnet_exposed_scores_high():
    asset = _asset(
        hostname="switch.example.com",
        services=[Service(port=23, service_name="telnet")],
        tls=TlsInfo(enabled=False),
    )
    scored = score_asset(asset)
    assert scored.score >= 25
    assert any("Telnet" in f.description for f in scored.findings)


def test_smb_exposed_flagged():
    asset = _asset(
        hostname="fileshare.example.com",
        services=[Service(port=445, service_name="microsoft-ds")],
        tls=TlsInfo(enabled=False),
    )
    scored = score_asset(asset)
    assert any(f.category == "exposed_port" and "445" in f.description for f in scored.findings)


def test_admin_panel_hostname_flagged():
    asset = _asset(
        hostname="admin.example.com",
        services=[Service(port=443, service_name="https")],
    )
    scored = score_asset(asset)
    assert any(f.category == "admin_panel" for f in scored.findings)


def test_staging_hostname_flagged_sensitive():
    asset = _asset(hostname="staging.example.com", services=[])
    scored = score_asset(asset)
    assert any(f.category == "sensitive_hostname" for f in scored.findings)


def test_vpn_hostname_flagged_sensitive():
    asset = _asset(hostname="vpn.example.com", services=[])
    scored = score_asset(asset)
    assert any(f.category == "sensitive_hostname" and "vpn" in f.description.lower() for f in scored.findings)


def test_outdated_apache_version_flagged():
    asset = _asset(
        hostname="legacy-web.example.com",
        services=[Service(port=80, service_name="http", product="Apache", version="2.2.15")],
    )
    scored = score_asset(asset)
    assert any(f.category == "outdated_software" for f in scored.findings)


def test_current_nginx_version_not_flagged_outdated():
    asset = _asset(
        hostname="modern-web.example.com",
        services=[Service(port=443, service_name="https", product="nginx", version="1.25.3")],
    )
    scored = score_asset(asset)
    assert not any(f.category == "outdated_software" for f in scored.findings)


def test_expired_tls_flagged():
    asset = _asset(
        hostname="old-cert.example.com",
        services=[Service(port=443, service_name="https")],
        tls=TlsInfo(enabled=True, issuer="Internal CA", valid_to="2024-01-01", expired=True, self_signed=True),
    )
    scored = score_asset(asset)
    assert any(f.category == "expired_tls" for f in scored.findings)
    assert any(f.category == "self_signed_tls" for f in scored.findings)


def test_missing_tls_on_http_flagged():
    asset = _asset(
        hostname="plaintext.example.com",
        services=[Service(port=80, service_name="http")],
        tls=TlsInfo(enabled=False),
    )
    scored = score_asset(asset)
    assert any(f.category == "missing_tls" for f in scored.findings)


def test_s3_misconfig_tag_flagged():
    asset = _asset(
        hostname="reports-bucket.example.com",
        services=[Service(port=443, service_name="https", product="AWS S3")],
        tags=["public-bucket", "s3-misconfig"],
    )
    scored = score_asset(asset)
    assert any(f.category == "storage_misconfig" for f in scored.findings)


def test_asset_with_no_services_and_boring_hostname_scores_low():
    asset = _asset(hostname="status.example.com", services=[])
    scored = score_asset(asset)
    assert scored.severity == "low"
    assert scored.score == 0


def test_prioritize_assets_sorts_descending_by_score():
    low = _asset(hostname="status.example.com", services=[])
    high = _asset(
        hostname="rdp.example.com",
        services=[Service(port=3389, service_name="ms-wbt-server")],
        tls=TlsInfo(enabled=False),
    )
    graph = AssetGraph(organization="Test", assets=[low, high])
    ranked = prioritize_assets(graph)
    assert ranked[0].hostname == "rdp.example.com"
    assert ranked[0].score >= ranked[1].score


def test_prioritize_assets_ties_broken_alphabetically():
    a = _asset(hostname="b-host.example.com", services=[])
    b = _asset(hostname="a-host.example.com", services=[])
    graph = AssetGraph(organization="Test", assets=[a, b])
    ranked = prioritize_assets(graph)
    assert ranked[0].hostname == "a-host.example.com"
    assert ranked[1].hostname == "b-host.example.com"


def test_prioritize_assets_empty_graph_returns_empty_list():
    graph = AssetGraph(organization="Empty", assets=[])
    ranked = prioritize_assets(graph)
    assert ranked == []


def test_multiple_risk_factors_compound_score():
    asset = _asset(
        hostname="admin-staging.example.com",
        services=[
            Service(port=3389, service_name="ms-wbt-server"),
            Service(port=80, service_name="http", product="Apache", version="2.2.15"),
        ],
        tls=TlsInfo(enabled=False),
    )
    scored = score_asset(asset)
    categories = {f.category for f in scored.findings}
    assert "exposed_port" in categories
    assert "outdated_software" in categories
    assert "sensitive_hostname" in categories
    assert "admin_panel" in categories
    assert scored.severity == "high"
