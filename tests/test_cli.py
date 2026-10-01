"""End-to-end CLI tests for recon_mapper.cli."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from recon_mapper.cli import cli


@pytest.fixture
def sample_data_path():
    return "sample_data/assets.json"


@pytest.fixture
def minimal_input_file(tmp_path):
    data = {
        "organization": "CLI Test Org",
        "assets": [
            {
                "asset_id": "a1",
                "hostname": "rdp.example.com",
                "ip_addresses": ["10.0.0.1"],
                "services": [{"port": 3389, "service_name": "ms-wbt-server"}],
                "tls": {"enabled": False},
            },
            {
                "asset_id": "a2",
                "hostname": "status.example.com",
                "ip_addresses": ["10.0.0.2"],
                "services": [{"port": 443, "service_name": "https", "product": "nginx", "version": "1.25.3"}],
                "tls": {"enabled": True, "expired": False},
            },
        ],
    }
    path = tmp_path / "input.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def test_cli_analyze_runs_end_to_end_on_sample_data(sample_data_path):
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", "--input", sample_data_path])
    assert result.exit_code == 0
    assert "ATTACK SURFACE REPORT" in result.output
    assert "HIGH" in result.output


def test_cli_analyze_json_only_outputs_valid_json(minimal_input_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", "--input", minimal_input_file, "--json-only"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["organization"] == "CLI Test Org"
    assert payload["total_assets"] == 2
    assert "ATTACK SURFACE REPORT" not in result.output


def test_cli_analyze_missing_file_errors_gracefully():
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", "--input", "sample_data/does_not_exist.json"])
    assert result.exit_code != 0
    assert "not found" in result.output.lower()


def test_cli_analyze_invalid_json_errors_gracefully(tmp_path):
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{not valid json", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", "--input", str(bad_file)])
    assert result.exit_code != 0
    assert "failed to parse" in result.output.lower()


def test_cli_analyze_empty_assets_list_errors(tmp_path):
    empty_file = tmp_path / "empty_assets.json"
    empty_file.write_text(json.dumps({"organization": "Empty", "assets": []}), encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", "--input", str(empty_file)])
    assert result.exit_code != 0
    assert "no assets found" in result.output.lower()


def test_cli_analyze_writes_output_file(minimal_input_file, tmp_path):
    output_path = tmp_path / "report.json"
    runner = CliRunner()
    result = runner.invoke(
        cli, ["analyze", "--input", minimal_input_file, "--output", str(output_path)]
    )
    assert result.exit_code == 0
    assert output_path.exists()
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["organization"] == "CLI Test Org"
    assert "Report written to" in result.output


def test_cli_analyze_high_risk_asset_surfaces_before_low_risk(minimal_input_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", "--input", minimal_input_file, "--json-only"])
    payload = json.loads(result.output)
    hostnames_in_order = [a["hostname"] for a in payload["assets"]]
    assert hostnames_in_order[0] == "rdp.example.com"


def test_cli_analyze_no_llm_flag_forces_offline(minimal_input_file, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "fake-key-should-be-ignored")
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", "--input", minimal_input_file, "--no-llm", "--json-only"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["total_assets"] == 2


def test_cli_help_lists_analyze_command():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "analyze" in result.output


def test_cli_analyze_help_lists_expected_flags():
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", "--help"])
    assert result.exit_code == 0
    assert "--input" in result.output
    assert "--json-only" in result.output
    assert "--output" in result.output
    assert "--use-llm" in result.output
