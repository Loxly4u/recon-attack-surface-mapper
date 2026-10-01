"""
Command-line entrypoint for the AI-Assisted Recon & Attack Surface Mapper.

This tool is OFFLINE ONLY: it ingests a pre-collected, sample/synthetic
recon JSON file. It does not make any live network calls, API calls, or
scans. See README.md for full scope and safety notes.

Usage:
    recon-mapper analyze --input sample_data/assets.json
    recon-mapper analyze --input sample_data/assets.json --json-only
    recon-mapper analyze --input sample_data/assets.json --output report.json --use-llm
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from recon_mapper.ingestion import load_recon_data
from recon_mapper.prioritization import prioritize_assets
from recon_mapper.reporting import AttackSurfaceReport, generate_report


def _report_to_dict(report: AttackSurfaceReport) -> dict:
    return {
        "organization": report.organization,
        "total_assets": report.total_assets,
        "high_count": report.high_count,
        "medium_count": report.medium_count,
        "low_count": report.low_count,
        "overview": report.overview,
        "assets": [
            {
                "asset_id": s.asset_id,
                "hostname": s.hostname,
                "score": s.score,
                "severity": s.severity,
                "narrative": s.narrative,
                "recommended_action": s.recommended_action,
                "findings": s.finding_descriptions,
            }
            for s in report.asset_summaries
        ],
    }


def _print_report(report: AttackSurfaceReport) -> None:
    click.echo(f"\n{'=' * 70}")
    click.echo(f"ATTACK SURFACE REPORT — {report.organization}")
    click.echo(f"{'=' * 70}\n")
    click.echo(report.overview)
    click.echo(
        f"\nTotals: {report.total_assets} asset(s) — "
        f"{report.high_count} high, {report.medium_count} medium, {report.low_count} low\n"
    )

    for s in report.asset_summaries:
        click.echo(f"[{s.severity.upper()}] {s.hostname} (score {s.score})")
        click.echo(f"  Summary:     {s.narrative}")
        click.echo(f"  Recommended: {s.recommended_action}")
        click.echo("")


@click.group()
def cli() -> None:
    """AI-Assisted Recon & Attack Surface Mapper (offline, sample-data only)."""


@cli.command()
@click.option(
    "--input", "input_path", required=True, type=click.Path(),
    help="Path to a sample/synthetic recon JSON file (pre-collected data only).",
)
@click.option(
    "--use-llm/--no-llm", default=None,
    help="Force LLM-based narrative generation on/off. Default: auto-detect via OPENAI_API_KEY.",
)
@click.option(
    "--output", "output_path", default=None, type=click.Path(),
    help="If set, write the JSON report to this file.",
)
@click.option(
    "--json-only", is_flag=True, default=False,
    help="Print only the JSON report to stdout (suppress human-readable report).",
)
def analyze(
    input_path: str,
    use_llm: bool | None,
    output_path: str | None,
    json_only: bool,
) -> None:
    """Run the full ingestion -> prioritization -> reporting pipeline."""
    try:
        graph = load_recon_data(input_path)
    except FileNotFoundError as exc:
        click.echo(str(exc), err=True)
        sys.exit(1)
    except ValueError as exc:
        click.echo(f"Failed to parse recon data: {exc}", err=True)
        sys.exit(1)

    if not graph.assets:
        click.echo("No assets found in input file.", err=True)
        sys.exit(1)

    scored_assets = prioritize_assets(graph)
    report = generate_report(graph.organization, scored_assets, use_llm=use_llm)

    if not json_only:
        _print_report(report)

    report_dict = _report_to_dict(report)

    if output_path:
        Path(output_path).write_text(json.dumps(report_dict, indent=2), encoding="utf-8")
        click.echo(f"Report written to {output_path}")
    elif json_only:
        click.echo(json.dumps(report_dict, indent=2))


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
