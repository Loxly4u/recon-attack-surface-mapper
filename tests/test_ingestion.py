"""Tests for recon_mapper.ingestion."""

from __future__ import annotations

import json

import pytest

from recon_mapper.ingestion import (
    Asset,
    AssetGraph,
    load_recon_data,
    parse_recon_data,
)


def _minimal_data(**overrides):
    data = {
        "organization": "Test Org",
        "assets": [
            {
                "asset_id": "a1",
                "hostname": "host1.example.com",
                "ip_addresses": ["10.0.0.1"],
                "services": [
                    {"port": 443, "protocol": "tcp", "service_name": "https", "product": "nginx", "version": "1.25.0"}
                ],
                "tech_stack": ["nginx"],
                "tls": {"enabled": True, "issuer": "Let's Encrypt", "valid_to": "2026-01-01", "expired": False},
                "tags": ["production"],
            }
        ],
    }
    data.update(overrides)
    return data


def test_parse_recon_data_basic_shape():
    graph = parse_recon_data(_minimal_data())
    assert isinstance(graph, AssetGraph)
    assert graph.organization == "Test Org"
    assert len(graph.assets) == 1
    asset = graph.assets[0]
    assert isinstance(asset, Asset)
    assert asset.hostname == "host1.example.com"
    assert asset.ip_addresses == ["10.0.0.1"]
    assert asset.ports == [443]


def test_parse_recon_data_missing_assets_key_raises():
    with pytest.raises(ValueError):
        parse_recon_data({"organization": "No Assets Org"})


def test_parse_recon_data_assets_not_a_list_raises():
    with pytest.raises(ValueError):
        parse_recon_data({"organization": "Bad Org", "assets": "not-a-list"})


def test_parse_recon_data_not_a_dict_raises():
    with pytest.raises(ValueError):
        parse_recon_data(["unexpected", "list"])


def test_parse_recon_data_defaults_organization_when_missing():
    graph = parse_recon_data({"assets": []})
    assert graph.organization == "Unknown Organization"
    assert len(graph.assets) == 0


def test_parse_asset_defaults_asset_id_from_hostname_when_missing():
    data = _minimal_data()
    del data["assets"][0]["asset_id"]
    graph = parse_recon_data(data)
    assert graph.assets[0].asset_id == "host1.example.com"


def test_parse_asset_accepts_single_ip_string_instead_of_list():
    data = _minimal_data()
    data["assets"][0]["ip_addresses"] = "10.0.0.5"
    graph = parse_recon_data(data)
    assert graph.assets[0].ip_addresses == ["10.0.0.5"]


def test_parse_asset_handles_missing_tls_block():
    data = _minimal_data()
    del data["assets"][0]["tls"]
    graph = parse_recon_data(data)
    assert graph.assets[0].tls.enabled is False


def test_parse_service_missing_port_raises():
    data = _minimal_data()
    data["assets"][0]["services"] = [{"service_name": "https"}]
    with pytest.raises(ValueError):
        parse_recon_data(data)


def test_parse_asset_alternate_field_names_ips_and_ports():
    data = _minimal_data()
    data["assets"][0].pop("ip_addresses")
    data["assets"][0]["ips"] = ["10.0.0.9"]
    data["assets"][0].pop("services")
    data["assets"][0]["ports"] = [{"port": 22, "service_name": "ssh"}]
    graph = parse_recon_data(data)
    asset = graph.assets[0]
    assert asset.ip_addresses == ["10.0.0.9"]
    assert asset.ports == [22]


def test_load_recon_data_missing_file_raises_file_not_found(tmp_path):
    missing_path = tmp_path / "does_not_exist.json"
    with pytest.raises(FileNotFoundError):
        load_recon_data(missing_path)


def test_load_recon_data_empty_file_raises_value_error(tmp_path):
    empty_path = tmp_path / "empty.json"
    empty_path.write_text("   ", encoding="utf-8")
    with pytest.raises(ValueError):
        load_recon_data(empty_path)


def test_load_recon_data_invalid_json_raises_value_error(tmp_path):
    bad_path = tmp_path / "bad.json"
    bad_path.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(ValueError):
        load_recon_data(bad_path)


def test_load_recon_data_valid_file_roundtrip(tmp_path):
    path = tmp_path / "assets.json"
    path.write_text(json.dumps(_minimal_data()), encoding="utf-8")
    graph = load_recon_data(path)
    assert graph.organization == "Test Org"
    assert len(graph.assets) == 1


def test_load_sample_data_file_parses_successfully():
    graph = load_recon_data("sample_data/assets.json")
    assert len(graph.assets) >= 10
    assert graph.organization
    hostnames = [a.hostname for a in graph.assets]
    assert len(hostnames) == len(set(hostnames))
