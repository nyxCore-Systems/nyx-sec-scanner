# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single-file bash scanner (`sec-scan.sh`, ~1300 lines) that detects npm supply-chain IOCs (Shai-Hulud, qix/chalk-debug, nx) on a developer workstation and emits an audit-ready report mapped to ISO 27001 / GDPR / BSI / NIS2. There is no build step, no package manager, no source-and-bundle split — the script *is* the product.

## Commands

```bash
# Syntax + lint exactly as CI runs them (.github/workflows/shellcheck.yml).
bash -n sec-scan.sh
shellcheck -e SC2155 -e SC2086 -e SC1091 sec-scan.sh

# Run the scanner against the current directory.
./sec-scan.sh --dry-run                       # read-only, no FS modifications
./sec-scan.sh                                 # default: auto-fix safe perms
./sec-scan.sh --quarantine                    # move flagged files to ~/.sec-scan-quarantine/<ts>/
./sec-scan.sh ~/Projects/some-app             # target a specific project
./sec-scan.sh --purge                         # GDPR Art. 17 right to erasure
```

There is no test suite. CI is `bash -n` + shellcheck only. Verify behavioural changes by running `--dry-run` against a real project and diffing the produced report under `~/.dev-security/scan-report_<ts>.md`.

## Architecture

`sec-scan.sh` is divided into 10 numbered sections (the `section "N · …"` calls map 1:1 to headings in the generated markdown report — they are the operator-facing contract, not just organisational comments):

| Section | Role |
|---|---|
| 1 | Project root discovery (walks up from `$PROJECT_ARG` or cwd looking for `package.json`) |
| 2 | System prereqs + early registry-hijack abort |
| 3 | Worm IOC scan: filesystem, `/tmp` staging, macOS Application Support, git hooks (per-repo + global `core.hooksPath`), `package-lock.json` cross-check, malicious workflows, shell-rc, cron/launchd |
| 4 | `npm audit` (single Node parser, DRY) |
| 5 | Postinstall hook inventory |
| 6 | `.env` permission check |
| 7 | Git hygiene |
| 8 | SSH key security |
| 9 | `npm` registry + `.npmrc` |
| 10 | Summary + JSON sidecar + SHA-256 tamper-evidence + optional notify-email |

Helpers live at the top of the file (~lines 100–185): `log`, `ok`, `warn`, `err`, `section`, `rep`, `rep_path`, `rep_redact`, `bump`, `do_action`, `quarantine`, `check_active_worm_procs`, `file_perms`, `ioc_format_ok`. New checks should use these — `rep` writes to the markdown report, `rep_path` relativises `$HOME` → `~/`, `rep_redact` strips 20+-char token-like substrings, `bump` increments counters, and `do_action` is the central dispatch that honours `--dry-run` / `--quarantine`.

Static IOC list: the `COMPROMISED[]` array (~lines 470–490). To add IOCs locally, edit this array; for fleet-wide updates, host an HTTPS feed and use `SEC_SCAN_IOC_URL` (+ optionally `SEC_SCAN_IOC_SHA256`) instead — see `docs/IOC-FEED.md`. Every entry is validated at startup via `ioc_format_ok`; a malformed entry causes exit code 4.

## Invariants that constrain every change

These are **anti-features** documented in `docs/ARCHITECTURE.md`. Do not regress them:

- **Never auto-delete.** Suspicious files are *moved* to `~/.sec-scan-quarantine/<ts>/`, never `rm`'d. Only `--purge` deletes, and only after a `YES` prompt.
- **Never auto-kill processes.** `check_active_worm_procs` warns; the operator decides. No `kill -9` from a security scanner.
- **Never auto-rotate credentials.** Worm hits emit a checklist in the report.
- **Never phone home.** No telemetry, no version-check ping, no auto-update.
- **Abort before `npm audit fix` if the registry is not `https://registry.npmjs.org/`** (exit code 3). Registry hijack check must remain *before* any audit-fix invocation.
- **`set -euo pipefail` is non-negotiable.** Bash is fragile; lose this and silent failures become the default.

## GDPR / privacy contract

The report is treated as a regulated artefact. When adding output:

- Default-pseudonymise: log machine ID (SHA-256 of hostname+user, truncated). Raw hostname / user / SSH-key filenames only behind `--include-identity`.
- **Never** log verbatim crontab or shell-rc content. Only redacted matching lines, with 20+-char tokens replaced by `[REDACTED]` via `rep_redact`.
- All paths in the report relativised via `rep_path` (`$HOME` → `~/`).
- Report directory is `install -d -m 700`; report files are `chmod 600`. The `.sha256` sidecar is the tamper-evidence anchor — keep it written *after* the markdown report is finalised.
- **`--notify-email` attaches the full report, JSON sidecar, and SHA-256 to the message** (multipart/mixed for sendmail/msmtp; `-a` flags for mailx/mail). This transmits operational security data via the configured MTA — recipient mailbox and transport security become the controller's responsibility once the mail leaves the host. Do not enable this path by default.

## Exit codes (stable contract — used by automation)

`0` clean · `1` manual actions required · `2` worm IOC hit · `3` registry-hijack abort · `4` malformed IOC entry · `5` IOC feed integrity check failed.

## Environment variables

`SEC_SCAN_IOC_URL` (HTTPS-only live feed), `SEC_SCAN_IOC_SHA256` (feed pin), `SEC_SCAN_NOTIFY_EMAIL` (summary recipient; auto-detects `mailx`/`mail`/`msmtp`/`sendmail`, fail-silent if no MTA), `SEC_SCAN_RETENTION_DAYS` (default 90, auto-purges old reports on next run).

## Extending

- **New persistence check** → model after the git-hook scan in section 3a-git (recursive `find` with depth bound, pattern grep, `do_action` for any mutation).
- **New compliance framework mapping** → extend `docs/COMPLIANCE.md` *and* the JSON sidecar fields at the end of section 10. The markdown report and JSON sidecar are parallel surfaces; both must stay in sync.
- **Changes to report section headings** → these are the audit-evidence contract. Renaming `## 3. Worm / supply-chain IOC scan` breaks downstream parsers and compliance mappings. Add sections, don't rename them.
