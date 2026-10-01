"""
Attack surface prioritization / scoring engine.

Ranks normalized assets by estimated exploitability and business impact
using fully offline, deterministic heuristics. No network calls, no live
scanning, no external services -- scoring is a pure function of the
pre-collected recon data already present in the AssetGraph.

Risk factors considered:
  - High-risk exposed ports (e.g. RDP 3389, Telnet 23, SMB 445)
  - Exposed admin/management panels
  - Outdated or end-of-life software versions
  - Missing or weak TLS (absent, expired, self-signed)
  - Sensitive-sounding hostnames (staging, admin, vpn, dev, internal, etc.)
  - Cloud storage / bucket misconfiguration style findings (via tags/notes)
"""

from __future__ import annotations

from dataclasses import dataclass, field

from recon_mapper.ingestion import Asset, AssetGraph, Service

# Ports widely considered high-risk when exposed to the internet.
HIGH_RISK_PORTS: dict[int, str] = {
    23: "Telnet exposed (unencrypted remote admin access)",
    3389: "RDP exposed (common ransomware entry vector)",
    445: "SMB exposed (EternalBlue/ransomware propagation vector)",
    21: "FTP exposed (often unencrypted/anonymous access)",
    135: "MS-RPC exposed",
    139: "NetBIOS exposed",
    5900: "VNC exposed (often weak/no auth)",
    6379: "Redis exposed (often unauthenticated)",
    9200: "Elasticsearch exposed (often unauthenticated)",
    27017: "MongoDB exposed (often unauthenticated)",
    3306: "MySQL exposed directly to the internet",
    5432: "PostgreSQL exposed directly to the internet",
}

MEDIUM_RISK_PORTS: dict[int, str] = {
    22: "SSH exposed",
    25: "SMTP exposed",
    110: "POP3 exposed",
    143: "IMAP exposed",
}

# Hostname substrings that often indicate a forgotten/under-protected asset.
SENSITIVE_HOSTNAME_KEYWORDS: dict[str, str] = {
    "admin": "Admin-sounding subdomain suggests a management interface",
    "staging": "Staging environment, often less hardened than production",
    "stage": "Staging environment, often less hardened than production",
    "test": "Test environment, often less hardened than production",
    "dev": "Development environment, often less hardened than production",
    "vpn": "VPN endpoint, high-value target for initial access",
    "internal": "Internal-sounding host unexpectedly internet-facing",
    "backup": "Backup system, may expose sensitive data",
    "db": "Database-sounding host, high data-sensitivity target",
    "jenkins": "CI/CD system, common pivot point for supply-chain attacks",
    "preprod": "Pre-production environment, often less hardened",
    "demo": "Demo environment, often forgotten and unpatched",
    "legacy": "Legacy system, likely outdated and unpatched",
    "old": "Legacy-sounding host, likely outdated and unpatched",
    "sandbox": "Sandbox environment, may have relaxed security controls",
}

ADMIN_PANEL_KEYWORDS = (
    "admin", "wp-admin", "phpmyadmin", "cpanel", "webmin", "management",
    "dashboard", "portainer", "pgadmin", "manager",
)

MISCONFIG_TAG_KEYWORDS = (
    "public-bucket", "open-bucket", "s3-misconfig", "bucket-misconfig",
    "public-read", "world-readable", "exposed-storage",
)

# Multi-word phrases checked against free-text notes only (not single
# generic words like "misconfigured", which produce false positives when
# notes describe unrelated issues such as firewall/ACL misconfiguration).
MISCONFIG_NOTE_PHRASES = (
    "public-read acl", "public read acl", "publicly readable",
    "bucket misconfig", "open s3 bucket", "world-readable bucket",
)

# End-of-life / known-outdated major versions for common software, expressed
# as an inclusive upper bound: version string prefixes <= this are flagged.
# This is intentionally simple/heuristic, not a CVE database.
OUTDATED_VERSION_HINTS: dict[str, tuple[str, ...]] = {
    "apache": ("2.2.", "2.0.", "1."),
    "nginx": ("1.1.", "1.0.", "0."),
    "openssh": ("5.", "6.", "4."),
    "iis": ("6.0", "7.0", "7.5"),
    "php": ("5.", "4."),
    "vsftpd": ("2.3.4",),
    "wordpress": ("4.", "3.", "2."),
}


@dataclass
class RiskFinding:
    """A single contributing risk factor for an asset."""

    category: str
    description: str
    weight: int


@dataclass
class ScoredAsset:
    """An asset annotated with its computed risk score and findings."""

    asset: Asset
    score: int
    severity: str
    findings: list[RiskFinding] = field(default_factory=list)

    @property
    def hostname(self) -> str:
        return self.asset.hostname


def _score_ports(services: list[Service]) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    for svc in services:
        if svc.port in HIGH_RISK_PORTS:
            findings.append(
                RiskFinding(
                    category="exposed_port",
                    description=f"Port {svc.port}/{svc.protocol}: {HIGH_RISK_PORTS[svc.port]}",
                    weight=25,
                )
            )
        elif svc.port in MEDIUM_RISK_PORTS:
            findings.append(
                RiskFinding(
                    category="exposed_port",
                    description=f"Port {svc.port}/{svc.protocol}: {MEDIUM_RISK_PORTS[svc.port]}",
                    weight=8,
                )
            )
    return findings


def _score_admin_panels(asset: Asset) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    haystacks = [asset.hostname.lower()]
    for svc in asset.services:
        if svc.banner:
            haystacks.append(svc.banner.lower())
    for svc in asset.services:
        service_name = (svc.service_name or "").lower()
        haystacks.append(service_name)

    combined = " ".join(haystacks)
    for keyword in ADMIN_PANEL_KEYWORDS:
        if keyword in combined:
            findings.append(
                RiskFinding(
                    category="admin_panel",
                    description=f"Possible exposed admin/management panel (matched '{keyword}')",
                    weight=20,
                )
            )
            break  # avoid double-counting multiple keyword hits on same asset
    return findings


def _score_outdated_software(services: list[Service]) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    for svc in services:
        product = (svc.product or "").lower()
        version = svc.version or ""
        if not product or not version:
            continue
        for known_product, outdated_prefixes in OUTDATED_VERSION_HINTS.items():
            if known_product in product:
                if any(version.startswith(prefix) for prefix in outdated_prefixes):
                    findings.append(
                        RiskFinding(
                            category="outdated_software",
                            description=(
                                f"Outdated {svc.product} {version} detected on port "
                                f"{svc.port} (known EOL/vulnerable version range)"
                            ),
                            weight=18,
                        )
                    )
    return findings


def _score_tls(asset: Asset) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    has_web_service = any(s.port in (443, 8443) or "https" in (s.service_name or "").lower() for s in asset.services)
    has_http = any(s.port == 80 or (s.service_name or "").lower() == "http" for s in asset.services)

    if has_http and not asset.tls.enabled:
        findings.append(
            RiskFinding(
                category="missing_tls",
                description="HTTP service exposed without TLS (plaintext traffic)",
                weight=12,
            )
        )
    if asset.tls.enabled and asset.tls.expired:
        findings.append(
            RiskFinding(
                category="expired_tls",
                description=f"TLS certificate expired (valid_to={asset.tls.valid_to})",
                weight=15,
            )
        )
    if asset.tls.enabled and asset.tls.self_signed:
        findings.append(
            RiskFinding(
                category="self_signed_tls",
                description="Self-signed TLS certificate in use",
                weight=6,
            )
        )
    if not has_web_service and not has_http:
        pass  # non-web asset: TLS posture not applicable
    return findings


def _score_sensitive_hostname(asset: Asset) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    hostname_lower = asset.hostname.lower()
    matched: set[str] = set()
    for keyword, description in SENSITIVE_HOSTNAME_KEYWORDS.items():
        if keyword in hostname_lower and keyword not in matched:
            findings.append(
                RiskFinding(
                    category="sensitive_hostname",
                    description=f"Hostname contains '{keyword}': {description}",
                    weight=10,
                )
            )
            matched.add(keyword)
    return findings


def _score_misconfig_tags(asset: Asset) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    tags_haystack = " ".join(asset.tags).lower()
    notes_haystack = (asset.notes or "").lower()

    for keyword in MISCONFIG_TAG_KEYWORDS:
        if keyword in tags_haystack:
            findings.append(
                RiskFinding(
                    category="storage_misconfig",
                    description=f"Possible storage/bucket misconfiguration (matched tag '{keyword}')",
                    weight=22,
                )
            )
            return findings

    for phrase in MISCONFIG_NOTE_PHRASES:
        if phrase in notes_haystack:
            findings.append(
                RiskFinding(
                    category="storage_misconfig",
                    description=f"Possible storage/bucket misconfiguration (matched note phrase '{phrase}')",
                    weight=22,
                )
            )
            return findings

    return findings


def _severity_for_score(score: int) -> str:
    if score >= 25:
        return "high"
    if score >= 10:
        return "medium"
    return "low"


def score_asset(asset: Asset) -> ScoredAsset:
    """Compute a deterministic offline risk score for a single asset."""
    findings: list[RiskFinding] = []
    findings.extend(_score_ports(asset.services))
    findings.extend(_score_admin_panels(asset))
    findings.extend(_score_outdated_software(asset.services))
    findings.extend(_score_tls(asset))
    findings.extend(_score_sensitive_hostname(asset))
    findings.extend(_score_misconfig_tags(asset))

    total_score = sum(f.weight for f in findings)
    severity = _severity_for_score(total_score)

    return ScoredAsset(asset=asset, score=total_score, severity=severity, findings=findings)


def prioritize_assets(graph: AssetGraph) -> list[ScoredAsset]:
    """
    Score every asset in the graph and return them sorted by descending
    risk score (highest priority first). Ties are broken alphabetically by
    hostname for deterministic output.
    """
    scored = [score_asset(asset) for asset in graph.assets]
    scored.sort(key=lambda sa: (-sa.score, sa.hostname))
    return scored
