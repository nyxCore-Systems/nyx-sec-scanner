# nyx-sec-scanner

A zero-dependency bash scanner that hardens a developer workstation against the **npm supply-chain worm wave of 2025** (Shai-Hulud, qix/chalk-debug, nx) and produces an **audit-ready report** mapped to ISO 27001:2022 + GDPR/DSGVO + BSI IT-Grundschutz + NIS2 controls.

It is a **scanner**, not an EDR. It detects known IOCs, hardens file permissions, and produces evidence. Organisational compliance still requires the org to operationalise the output.

## Features

- **Worm IOC scan**: Shai-Hulud filesystem artifacts, compromised npm package versions (static + optional live feed) — auto-detects **npm** (`package-lock.json`) or **pnpm** (`pnpm-lock.yaml`) projects and runs the matching audit / lockfile-scan; tampered GitHub workflows, malicious git hooks (per-repo + global `core.hooksPath`), `/tmp` staging payloads, macOS `~/Library/Application Support` persistence, shell-rc injection patterns, suspicious crontab entries.
- **Permission hardening**: `.env`, `~/.ssh`, `~/.npmrc`, per-key (only flags + fixes deviations from `600/700`).
- **Registry hijack check**: aborts BEFORE any `npm audit fix` if the active registry is not `https://registry.npmjs.org/`.
- **Active-process detection**: warns when worm-like processes hold an open fd to a quarantine target.
- **GDPR by default**: pseudonymised machine ID; raw hostname/user/SSH-key filenames only via opt-in `--include-identity`; verbatim crontab and `.bashrc` snippets never logged (only redacted matching lines).
- **Tamper-evident report**: SHA-256 fingerprint appended inline + sidecar `.sha256` (mode 600).
- **JSON sidecar** for SIEM/Splunk/ELK/Wazuh ingestion.
- **Right to erasure** (`--purge`) — drops all reports + quarantine on operator confirmation.
- **Optional incident email with attachments** (`--notify-email <addr>` or `SEC_SCAN_NOTIFY_EMAIL` env) via `mailx`/`mail`/`msmtp`/`sendmail` — markdown report, JSON sidecar, and SHA-256 fingerprint are attached to the message.
- **90-day retention auto-enforce** (configurable via `SEC_SCAN_RETENTION_DAYS`).

## Install

```bash
git clone https://github.com/nyxCore-Systems/nyx-sec-scanner.git
cd nyx-sec-scanner
chmod +x sec-scan.sh
sudo install -m 755 sec-scan.sh /usr/local/bin/    # optional: globally available
```

**Do not** `curl ... | bash`. Inspect the script before running.

## Usage

```bash
# Default: scan + auto-fix safe permission issues. Report flagged items.
./sec-scan.sh

# Report only — no modifications.
./sec-scan.sh --dry-run

# Move suspicious files to ~/.sec-scan-quarantine/<timestamp>/
./sec-scan.sh --quarantine

# Scan a specific project directory.
./sec-scan.sh ~/Projects/some-app

# Send a summary email when done (requires local MTA).
SEC_SCAN_NOTIFY_EMAIL=security@example.com ./sec-scan.sh
# or
./sec-scan.sh --notify-email security@example.com

# Pull live IOCs from your own (HTTPS-only) feed before scanning.
# Optionally pin its SHA-256 to defend against feed-poisoning.
SEC_SCAN_IOC_URL=https://your.feed/iocs.txt \
SEC_SCAN_IOC_SHA256=abc123... ./sec-scan.sh

# Verbose — keeps raw hostname/user/SSH-key names in the report (opt-in).
./sec-scan.sh --include-identity

# GDPR Art. 17 right to erasure — delete all reports + quarantine.
./sec-scan.sh --purge

# Skip live IOC fetch (offline scan against static list only).
./sec-scan.sh --no-live-ioc

# Force a specific package manager (auto-detected by default from lockfile).
SEC_SCAN_PM=pnpm ./sec-scan.sh
SEC_SCAN_PM=npm  ./sec-scan.sh
```

## Package-manager support

Auto-detected from the project's lockfile:

| Lockfile | Detected as | Audit command | Auto-fix command |
|---|---|---|---|
| `pnpm-lock.yaml` | `pnpm` | `pnpm audit --json` | `pnpm audit --fix --prod` |
| `package-lock.json` | `npm` | `npm audit --json` | `npm audit fix --omit=dev` |
| both present | `pnpm` (with warning to delete `package-lock.json`) | — | — |
| neither | from `packageManager` field in `package.json`, else `npm` | — | — |

Override with `SEC_SCAN_PM=pnpm` or `SEC_SCAN_PM=npm`. yarn is currently detected but falls back to npm-style checks (incomplete — open an issue if you need first-class yarn support).

The lockfile IOC cross-check parses each format directly (no `yq`/`jq` dependency for pnpm's YAML lockfile — handled via a Node regex sweep over the `packages:` section).

## Email notification

When `--notify-email <addr>` or `SEC_SCAN_NOTIFY_EMAIL` is set, the scanner sends a summary mail at the end of the run with **three attachments**:

| Attachment | MIME type |
|---|---|
| `scan-report_<ts>.md` | `text/markdown` |
| `scan-report_<ts>.json` | `application/json` |
| `scan-report_<ts>.sha256` | `text/plain` |

Transport auto-detection (in order): `mailx` → `mail` → `msmtp` → `sendmail`. If none is installed the mail step is skipped with a warning — the scan itself never fails because of mail.

**MTA compatibility**

| MTA | Attachment support | Notes |
|---|---|---|
| `msmtp -t` / `sendmail -t` | ✅ Full `multipart/mixed` MIME (RFC 2045, base64 ≤76 chars/line) | Recommended for production. |
| macOS `mail` / BSD `mailx` / s-nail | ✅ `-a FILE` per attachment | Works out of the box on macOS. |
| GNU mailutils `mail` (Debian/Ubuntu) | ❌ `-a` is repurposed for headers | Install `msmtp` or `sendmail` for reliable attachments. |

**Privacy implications**

Attaching the full report transmits operational security data — including the (pseudonymised) machine ID, scan findings, redacted matching lines from shell-rc/crontab, and IOC hits — across whatever MTA chain you have configured. Once the mail leaves the host, recipient mailbox security and transport encryption are the controller's responsibility under GDPR Art. 32(1)(a). Do not enable `--notify-email` against untrusted relays or shared inboxes.

If you only want the host-local artefacts and no outbound mail, simply omit the flag.

## Output

Each run produces three files under `~/.dev-security/` (mode 700 directory, mode 600 files):

| File | Purpose |
|------|---------|
| `scan-report_<ts>.md` | Operator-readable markdown report |
| `scan-report_<ts>.json` | Structured findings for SIEM ingestion |
| `scan-report_<ts>.sha256` | Tamper-evidence fingerprint (verify with `shasum -c`) |

Reports are auto-deleted after `SEC_SCAN_RETENTION_DAYS` (default 90) on next scan.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Clean — no issues |
| 1 | Manual actions required (review the report) |
| 2 | **Worm IOC hit** — rotate every credential reachable from the machine |
| 3 | Aborted — npm registry is not the default (possible hijack) |
| 4 | Malformed IOC entry — internal `COMPROMISED[]` array invalid |
| 5 | IOC feed integrity check failed |

## Compliance

Output is mapped to controls across four frameworks. See [`docs/COMPLIANCE.md`](docs/COMPLIANCE.md) for the full matrix.

> The scanner produces **evidence**. The organisation operationalises it (escalation, ticketing, retention review, audit packaging). This script alone does not certify your org against any framework.

## Threat model

Documented in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). Summary: this defends against opportunistic supply-chain compromise on developer workstations. It is not a substitute for endpoint EDR, an SBOM tool, or a SIEM.

## Contributing

PRs welcome. CI runs `shellcheck`. Vulnerabilities in the scanner itself: see [`SECURITY.md`](SECURITY.md).

## License

Apache 2.0 — see [`LICENSE`](LICENSE).
