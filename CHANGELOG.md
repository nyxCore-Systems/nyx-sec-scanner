# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.1] — 2026-05-19

### Added

- **Email attachments**: when `--notify-email` / `SEC_SCAN_NOTIFY_EMAIL` is configured, the markdown report, JSON sidecar, and SHA-256 fingerprint are attached to the notification mail instead of being referenced only by host-local path.
  - `msmtp` / `sendmail` path: proper RFC 2045 `multipart/mixed` MIME body, base64-encoded attachments wrapped at 76 chars (via `openssl base64`, fallback `base64 | tr | fold`).
  - `mailx` / `mail` path: one `-a FILE` per attachment (works on macOS `mail`, BSD `mailx`, s-nail; on GNU mailutils the send fails and the warning suggests installing `msmtp`/`sendmail`).
  - Missing artefacts (e.g. sidecar not yet written) are silently skipped — the mail still goes out with whatever exists.

### Security / privacy

- **Expanded data-protection surface**: attaching the full report means the configured MTA, its outbound relay, and the recipient mailbox are now part of the GDPR Art. 32(1)(a) responsibility. Document this when enabling `--notify-email` in production. Previously only metadata was transmitted.

## [2.1.0] — 2026-05-19 — First public release

### Added

- **Compliance-ready output** mapped to ISO 27001:2022 + GDPR/DSGVO + BSI IT-Grundschutz + NIS2 (see `docs/COMPLIANCE.md`).
- **Pseudonymised machine ID** (SHA-256 of hostname+user, 16-char truncated) — raw identifiers no longer in the report by default.
- **Privacy notice** in every report header citing GDPR Art. 6(1)(f) as lawful basis.
- **90-day retention auto-purge** of report directory + quarantine directory on script start. Configurable via `SEC_SCAN_RETENTION_DAYS`.
- **Tamper-evident SHA-256** fingerprint appended inline + sidecar `.sha256` file (mode 600).
- **JSON sidecar** `scan-report_<ts>.json` for SIEM ingestion (mode 600).
- **Optional email notification** via `--notify-email <addr>` or `SEC_SCAN_NOTIFY_EMAIL` env. Auto-detects `mailx`/`mail`/`msmtp`/`sendmail`. Fail-silent if no MTA.
- **`--purge` command** for GDPR Art. 17 right to erasure.
- **`--include-identity` opt-in flag** — exposes raw hostname/user/SSH-key filenames in the report (off by default).
- **`--verbose` and `--no-live-ioc` flags** for ops control.
- **IOC feed integrity verification** via `SEC_SCAN_IOC_SHA256` — refuses content that doesn't match.
- **HTTPS enforcement** on `SEC_SCAN_IOC_URL` — script refuses non-HTTPS feeds.
- **Report file mode 600 + dir mode 700** via `install -d -m 700` and `chmod 600`.
- **Path relativisation** — all logged paths replace `$HOME` with `~/`.
- **Crontab privacy** — verbatim content NEVER logged; only redacted matching lines for suspicious patterns.
- **Shell-rc redaction** — 20+-char token-like substrings replaced with `[REDACTED]` before writing.
- **SSH-key filename suppression** — labelled `private key #N` by default.
- **Apache 2.0 LICENSE**, `README.md`, `SECURITY.md`, `docs/COMPLIANCE.md`, `docs/ARCHITECTURE.md`, `docs/IOC-FEED.md`.
- **Shellcheck CI** workflow on PRs.

### Changed

- Default mode is `fix` (auto-corrects safe permissions). Use `--dry-run` for read-only scan.
- Exit codes reorganised: 0 clean, 1 manual actions, 2 worm hit, 3 registry hijack abort, 4 malformed IOC, 5 IOC feed integrity fail.

### Security

- Registry hijack detection runs **before** any `npm audit fix` — refuses to invoke audit-fix against a non-default registry.
- Active worm process check via `pgrep` runs before every quarantine `mv` (quarantine alone doesn't kill processes holding open fds).
- IOC array format validated at startup; malformed entries cause exit code 4.

## [2.0.x] — internal — Hardened pre-public

- Worm IOC scan (Shai-Hulud filesystem + lockfile + workflows).
- Single-flight refresh on JWKS-style cache pattern (internal reuse).
- DRY parsing of npm audit JSON.
- Color codes use real `$'\033[…m'` escape sequences.
- Bash arithmetic via `bump()` helper.

## [1.x] — internal — Initial draft

- Permission checks for `.env`, `~/.ssh`, `~/.npmrc`.
- npm audit integration.
- Postinstall hook inventory.
