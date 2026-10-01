"""
Recon data ingestion module.

Parses PRE-COLLECTED, SAMPLE/SYNTHETIC reconnaissance data (resembling the
kind of JSON export that tools such as Shodan, Censys, crt.sh, or a
subdomain-enumeration pipeline would produce) into a normalized internal
schema the rest of the pipeline (prioritization, reporting) can consume.

This module performs NO network calls and NO live scanning. It only reads
a local JSON file describing already-discovered assets.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class TlsInfo:
    """TLS certificate metadata for an asset, if any."""

    enabled: bool = False
    issuer: Optional[str] = None
    valid_to: Optional[str] = None
    expired: bool = False
    self_signed: bool = False


@dataclass
class Service:
    """A single open port/service observed on an asset."""

    port: int
    protocol: str = "tcp"
    service_name: str = "unknown"
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None


@dataclass
class Asset:
    """Normalized representation of a single discovered recon asset."""

    asset_id: str
    hostname: str
    ip_addresses: list[str] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    tech_stack: list[str] = field(default_factory=list)
    tls: TlsInfo = field(default_factory=TlsInfo)
    tags: list[str] = field(default_factory=list)
    source: str = "unknown"
    first_seen: Optional[str] = None
    notes: Optional[str] = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def ports(self) -> list[int]:
        return [s.port for s in self.services]


@dataclass
class AssetGraph:
    """Collection of all normalized assets for an organization's attack surface."""

    organization: str
    assets: list[Asset] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.assets)

    def __iter__(self):
        return iter(self.assets)


def _parse_tls(raw: dict[str, Any] | None) -> TlsInfo:
    if not raw:
        return TlsInfo(enabled=False)
    return TlsInfo(
        enabled=bool(raw.get("enabled", True)),
        issuer=raw.get("issuer"),
        valid_to=raw.get("valid_to"),
        expired=bool(raw.get("expired", False)),
        self_signed=bool(raw.get("self_signed", False)),
    )


def _parse_service(raw: dict[str, Any]) -> Service:
    try:
        port = int(raw.get("port"))
    except (TypeError, ValueError):
        raise ValueError(f"Service entry missing a valid 'port': {raw!r}")
    return Service(
        port=port,
        protocol=str(raw.get("protocol", "tcp")),
        service_name=str(raw.get("service_name") or raw.get("service") or "unknown"),
        product=raw.get("product"),
        version=raw.get("version"),
        banner=raw.get("banner"),
    )


def _parse_asset(raw: dict[str, Any]) -> Asset:
    asset_id = str(raw.get("asset_id") or raw.get("id") or raw.get("hostname") or "unknown-asset")
    hostname = str(raw.get("hostname") or raw.get("subdomain") or asset_id)

    ip_addresses_raw = raw.get("ip_addresses") or raw.get("ips") or []
    if isinstance(ip_addresses_raw, str):
        ip_addresses = [ip_addresses_raw]
    else:
        ip_addresses = [str(ip) for ip in ip_addresses_raw]

    services_raw = raw.get("services") or raw.get("ports") or []
    services = [_parse_service(s) for s in services_raw]

    tech_stack_raw = raw.get("tech_stack") or raw.get("technologies") or []
    tech_stack = [str(t) for t in tech_stack_raw]

    tags_raw = raw.get("tags") or []
    tags = [str(t) for t in tags_raw]

    return Asset(
        asset_id=asset_id,
        hostname=hostname,
        ip_addresses=ip_addresses,
        services=services,
        tech_stack=tech_stack,
        tls=_parse_tls(raw.get("tls") or raw.get("tls_cert")),
        tags=tags,
        source=str(raw.get("source", "unknown")),
        first_seen=raw.get("first_seen"),
        notes=raw.get("notes"),
        raw=raw,
    )


def parse_recon_data(data: dict[str, Any]) -> AssetGraph:
    """Parse an already-loaded recon JSON dict into an AssetGraph."""
    if not isinstance(data, dict):
        raise ValueError("Recon data must be a JSON object with an 'assets' array.")

    organization = str(data.get("organization", "Unknown Organization"))
    assets_raw = data.get("assets")
    if assets_raw is None:
        raise ValueError("Recon data is missing required 'assets' array.")
    if not isinstance(assets_raw, list):
        raise ValueError("'assets' must be a JSON array.")

    assets = [_parse_asset(a) for a in assets_raw]
    return AssetGraph(organization=organization, assets=assets)


def load_recon_data(path: str | Path) -> AssetGraph:
    """
    Load and parse a sample recon JSON file from disk.

    Raises FileNotFoundError if the path does not exist, and ValueError if
    the content is not valid JSON or does not match the expected schema.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Recon data file not found: {file_path}")

    content = file_path.read_text(encoding="utf-8").strip()
    if not content:
        raise ValueError(f"Recon data file is empty: {file_path}")

    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in recon data file {file_path}: {exc}") from exc

    return parse_recon_data(data)
