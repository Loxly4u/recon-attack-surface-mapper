# AI-Assisted Recon & Attack Surface Mapper

An offline tool that ingests **pre-collected, sample/synthetic** reconnaissance
data (the kind of JSON export that tools like Shodan, Censys, crt.sh, or a
subdomain-enumeration pipeline would produce) and turns it into a prioritized,
human-readable attack surface report — entirely offline, with no live network
calls or scans.

## Scope & safety note — read this first

**This is not a scanner.** It does not query Shodan/Censys/crt.sh, resolve
DNS, open sockets, or touch the network in any way. It only reads a local
JSON file describing *already-collected* recon findings and applies
offline scoring/reporting logic to it.

The included `sample_data/assets.json` describes a **fictional company**
("Northwind Retail Group") with synthetic hostnames, IPs (`203.0.113.0/24`,
a reserved documentation range per RFC 5737), and findings. No real
organization, infrastructure, or individual is represented.

This tool is a decision-support/triage aid for recon data you already
collected through your own authorized tooling. It does not replace manual
verification, and findings are heuristic, not a guarantee of exploitability.

## Why

Recon/OSINT tools can produce long lists of subdomains, IPs, open ports, and
fingerprints. Turning that raw list into "what should we fix first" is a
manual, repetitive task. This mapper:

1. **Ingests** a recon JSON export into a normalized `AssetGraph`/`Asset` model.
2. **Prioritizes** assets using deterministic, offline heuristics: exposed
   high-risk ports (RDP/Telnet/SMB/etc.), likely admin/management panels,
   outdated software versions, missing/expired/self-signed TLS, sensitive
   hostnames (`staging`, `admin`, `vpn`, ...), and storage-misconfiguration
   style findings.
3. **Reports** a natural-language narrative per high-priority asset plus an
   overall attack surface summary — offline template-based by default, with
   an optional pluggable LLM backend for richer narratives.

## Architecture

```
Pre-collected recon JSON (sample_data/assets.json)
        │
        ▼
┌─────────────────────┐
│  ingestion.py         │  Parses subdomains/IPs/ports/services/tech-stack/
└─────────────────────┘      TLS info into normalized Asset / AssetGraph
        │
        ▼
┌─────────────────────┐
│  prioritization.py    │  Offline heuristic scoring engine:
└─────────────────────┘      exposed high-risk ports, admin panels,
        │                     outdated software, missing/expired TLS,
        │                     sensitive hostnames, storage misconfig
        ▼
┌─────────────────────┐
│  reporting.py         │  Per-asset narrative + overall report.
└─────────────────────┘      Offline template by default; optional LLM
        │                     backend via OPENAI_API_KEY (graceful fallback)
        ▼
┌─────────────────────┐
│  cli.py               │  `recon-mapper analyze` — prints / writes report
└─────────────────────┘
```

## Setup

Requires Python 3.9+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Usage

Run the pipeline on the included sample data:

```bash
recon-mapper analyze --input sample_data/assets.json
```

Or without installing the console script:

```bash
python -m recon_mapper.cli analyze --input sample_data/assets.json
```

### Options

| Flag | Description |
|---|---|
| `--input PATH` | Path to a sample/synthetic recon JSON file (required). |
| `--use-llm` / `--no-llm` | Force LLM-based narrative generation on/off. Default: auto-detects via `OPENAI_API_KEY` env var. |
| `--output PATH` | Write the JSON report to a file. |
| `--json-only` | Print only the JSON report to stdout. |

### Example: JSON output

```bash
recon-mapper analyze --input sample_data/assets.json --json-only
```

### Example: write report to a file

```bash
recon-mapper analyze --input sample_data/assets.json --output report.json
```

### Optional: LLM-backed narratives

By default, per-asset and overall narratives are generated with a
deterministic offline template (no API calls, no cost). To use an LLM for
richer natural-language write-ups, install the `openai` package and set an
API key:

```bash
pip install openai
export OPENAI_API_KEY=sk-...
recon-mapper analyze --input sample_data/assets.json --use-llm
```

If the LLM call fails for any reason (no key, network error, bad response),
the pipeline automatically falls back to the offline template so it never
hard-fails. The LLM, if used, only ever receives the already-ingested
sample finding text — it does not perform any scanning itself.

## Input data format

`sample_data/assets.json` is a JSON object:

```json
{
  "organization": "Fictional Org Name",
  "assets": [
    {
      "asset_id": "asset-001",
      "hostname": "rdp-gateway.example.com",
      "ip_addresses": ["203.0.113.22"],
      "services": [
        {"port": 3389, "protocol": "tcp", "service_name": "ms-wbt-server", "product": "Microsoft Terminal Services", "version": "10.0"}
      ],
      "tech_stack": ["Windows Server 2016"],
      "tls": {"enabled": false},
      "tags": ["forgotten", "legacy-infra"],
      "notes": "Free-text analyst notes."
    }
  ]
}
```

Alternate field names are tolerated: `ips`/`ip_addresses`, `ports`/`services`,
`technologies`/`tech_stack`, and either a single IP string or a list.

## Scoring heuristics

Risk score is the sum of weighted findings per asset:

- High-risk exposed ports (RDP 3389, Telnet 23, SMB 445, FTP 21, VNC 5900,
  unauthenticated Redis/Elasticsearch/MongoDB, direct DB exposure, etc.) — heavy weight
- Possible exposed admin/management panel (hostname or service hints) — heavy weight
- Storage/bucket misconfiguration style findings (via tags or specific note phrasing) — heavy weight
- Outdated/EOL software versions (Apache, nginx, OpenSSH, PHP, IIS, vsftpd, WordPress) — moderate weight
- Expired TLS certificate — moderate weight
- Medium-risk exposed ports (SSH, SMTP, POP3/IMAP) — light weight
- Missing TLS on an HTTP service — light weight
- Self-signed TLS certificate — light weight
- Sensitive-sounding hostnames (`staging`, `admin`, `vpn`, `dev`, `internal`,
  `backup`, `jenkins`, `legacy`, etc.) — light weight per distinct keyword

Severity bands: **high** (score ≥ 25), **medium** (score ≥ 10), **low** (below).
This is an intentionally simple, explainable heuristic model — not a CVE
database or exploit predictor.

## Testing

```bash
pytest -v
```

50 tests cover ingestion (schema parsing, alternate field names, file I/O
error handling), prioritization (each risk factor, score compounding,
sorting/tie-breaking), reporting (offline narrative generation, LLM
fallback behavior), and the CLI (end-to-end run, JSON-only mode, output-file
mode, missing-file and invalid-JSON error handling).

## Project structure

```
recon-attack-surface-mapper/
├── src/recon_mapper/
│   ├── ingestion.py        # Recon JSON parsing & normalization
│   ├── prioritization.py   # Offline heuristic risk scoring engine
│   ├── reporting.py        # Narrative generation (offline/LLM)
│   └── cli.py               # Command-line entrypoint
├── tests/                  # pytest unit + CLI tests
├── sample_data/assets.json # Synthetic sample recon dataset
├── requirements.txt
└── pyproject.toml
```

## Limitations & disclaimers

- This is a portfolio/demonstration project operating on **sample/synthetic
  data only**. It is not a live scanner, does not integrate with any
  real OSINT API, and has not been validated against real-world recon
  exports at scale.
- Scoring is heuristic and intentionally simple (keyword/pattern matching
  on hostnames, ports, tags, and version strings) — it is not a CVE
  database, does not verify exploitability, and can both over- and
  under-flag findings relative to real-world risk.
- The offline reporter is template-based, not a true LLM — accurate but
  less nuanced than an LLM-generated narrative. The optional LLM path
  requires your own `OPENAI_API_KEY` and is subject to the usual LLM
  caveats (verify before acting on any auto-generated recommendation).
- Do not point any future live-data variant of this tool at infrastructure
  you do not own or have explicit authorization to assess.

## License

MIT
