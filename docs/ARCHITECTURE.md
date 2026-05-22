# Architecture

## Design choices

### Why bash, not Python / Go / Rust

- **Zero runtime dependencies on a fresh developer machine.** Every macOS and Linux dev box already has bash 4+. No `pip install`, no `cargo build`, no Node version to wrestle with.
- **Auditability.** A 1300-line shell script can be read end-to-end in 20 minutes by any senior engineer. A compiled binary cannot.
- **Single file.** `curl https://raw.../sec-scan.sh -o sec-scan.sh && shellcheck sec-scan.sh && chmod +x sec-scan.sh` is the entire install.
- **Trade-off**: bash is fragile around quoting, arrays, and error propagation. We compensate with `set -euo pipefail`, `bash -n` in CI, and `shellcheck` as a required check.

### Why open-source

Security tooling that ships in proprietary form is harder to trust. Open-source means anyone — including hostile reviewers — can verify the IOC list, the network calls, the file modifications, and the data the script writes to disk.

### Why a markdown report (not just JSON)

- The markdown report is for the **operator** — the developer running the scan reads it.
- The JSON sidecar is for **machines** — SIEM, ticketing, evidence-collection tools.
- Generating both costs negligible CPU and removes the "audit-vs-readable" trade-off.

---

## Threat model

### What the scanner defends against

| Threat | Mechanism |
|---|---|
| **Shai-Hulud worm filesystem persistence** | Direct path checks for `~/Shai-Hulud*`, shallow `find` for `bundle.js` / `shai*.js`, recent `/tmp/*.sh`, macOS `~/Library/Application Support` UUID-named directories. |
| **Compromised npm/pnpm package versions in the lockfile** | Static IOC array cross-checked against `package-lock.json` (npm, JSON) **or** `pnpm-lock.yaml` (pnpm, YAML regex-sweep) via Node-level parse. Manager is auto-detected from lockfile presence; override with `SEC_SCAN_PM=npm\|pnpm`. Optional live feed (HTTPS+SHA-256 pinned). |
| **Registry hijack via `.npmrc`** | Aborts the script BEFORE any `npm audit fix` if active registry is not `https://registry.npmjs.org/`. Cross-checks `_authToken` entries against the default registry host. |
| **Malicious GitHub Actions workflow injection** | Glob match for `*shai*` / `*hulud*` in `.github/workflows/`. |
| **Git hook persistence (per-repo + global `core.hooksPath`)** | Recursive find under `$HOME` (max-depth 4) for `post-commit`/`pre-push`/`post-checkout` hooks containing `curl|wget|shai|hulud` patterns. Plus explicit `git config --global core.hooksPath` check. |
| **Crontab / launchd persistence** | Pattern match on crontab content; LaunchAgent count surfaced for manual review. |
| **Shell-rc injection** | Pattern grep on `~/.bashrc`, `~/.zshrc`, `~/.profile` for curl-piped-sh / shai / hulud strings. |
| **Insecure file permissions** | `.env`, `~/.ssh`, `~/.npmrc` chmod hardening (only when modes deviate). |
| **Active worm process holding a file open during quarantine** | `pgrep -fl` for worm-indicator strings runs BEFORE every quarantine `mv`. The script does NOT auto-kill (deferred to operator) but warns prominently. |

### What the scanner does NOT defend against

- **Targeted attacks** against specific developers (this is opportunistic-scan tooling, not threat hunting).
- **Compromise at the OS / kernel level** — use endpoint EDR (Falcon, SentinelOne, Defender).
- **Compromise via browser extension** — out of scope.
- **Steal-then-clean attacks** — if the worm exfiltrates secrets and then deletes itself before the scan runs, the scanner finds nothing.
- **Zero-day npm compromises not yet in the IOC list** — supply chain security is a moving target; the live feed (`SEC_SCAN_IOC_URL`) is your operational hedge.
- **SBOM-level analysis** — for full software composition analysis use Syft / CycloneDX / Snyk.
- **Cross-machine correlation** — each scan stays local unless `--notify-email` is configured. There is no centralised fleet view.

### Adversary capability assumed

The scanner assumes an adversary with the capability to:

- Publish a malicious package to npm (Shai-Hulud actor profile).
- Compromise a maintainer account and push tainted versions to legitimate packages (qix Sep 2025 profile).
- Inject postinstall hooks that exfiltrate `$HOME` environment.
- Tamper with shell-rc, crontab, git hooks on infected machines for persistence.

It does **not** assume kernel-level rootkits, hypervisor compromise, or attackers with physical access. Defending against those requires defence-in-depth beyond a developer-workstation script.

---

## Trust boundaries

```
                            ┌──────────────────────────┐
                            │ Developer Workstation    │
                            │                          │
                            │  ┌────────────────────┐  │
                            │  │ sec-scan.sh (bash) │  │
                            │  └─────────┬──────────┘  │
                            │            │             │
   ┌────────────────────────┼────────────┼─────────────┼──────────────────────┐
   │                        │            │             │                      │
   ▼                        ▼            ▼             ▼                      ▼
┌──────────┐       ┌──────────────┐   ┌────────┐   ┌──────────┐    ┌──────────────────┐
│ npm      │       │ User HOME    │   │ /tmp   │   │ Local DB │    │ Optional outputs │
│ registry │       │ files+rc+ssh │   │ scan   │   │ ~/.dev-  │    │  • mail (M4)     │
│ (HTTPS)  │       │ (read+chmod) │   │        │   │ security │    │  • IOC feed pull │
└──────────┘       └──────────────┘   └────────┘   └──────────┘    └──────────────────┘
   ▲                                                                          ▲
   │                                                                          │
   │  Trust: registry == https://registry.npmjs.org/ (verified at startup)    │
   │  Trust: IOC feed URL is HTTPS, optionally SHA-256 pinned                 │
   │                                                                          │
   └──────────────────────────────────────────────────────────────────────────┘
                              External network
```

### Inbound trust

| Source | Trust assumption | Defence |
|---|---|---|
| `https://registry.npmjs.org/` | Default-only — abort if `npm config get registry` differs | Registry verification before `npm audit fix` |
| `SEC_SCAN_IOC_URL` | HTTPS-only; integrity verified iff `SEC_SCAN_IOC_SHA256` set | TLS 1.2 minimum, optional SHA-256 manifest check |
| Local filesystem (`$HOME`, `/tmp`) | Trusted to be readable; modifications are explicit (chmod / mv) | `--dry-run` mode for any operator who wants to inspect first |

### Outbound trust

| Destination | Data | Trust |
|---|---|---|
| `~/.dev-security/` | Report (md/json/sha256) — mode 600 | Local FS confidentiality (no encryption-at-rest beyond OS) |
| `~/.sec-scan-quarantine/` | Moved suspicious files | Local FS; operator inspects before deletion |
| Optional `--notify-email` recipient | Summary metadata + **attached** markdown report, JSON sidecar, SHA-256 fingerprint (multipart/mixed for sendmail/msmtp; `-a` per file for mailx/mail) | Operator's MTA + outbound relay + recipient inbox security. Attaching the full report widens the GDPR Art. 32(1)(a) surface — do not enable against untrusted relays. |

---

## Anti-features

This is what the scanner deliberately does **not** do:

- **No automatic process killing.** If `check_active_worm_procs` finds a suspect process, the operator decides whether to kill it. Auto-`kill -9` from a security scanner is its own footgun.
- **No automatic credential rotation.** Worm hits trigger a checklist in the report; the operator handles their own rotation.
- **No central upload.** A future "fleet view" feature is a separate sub-project with its own DPIA.
- **No telemetry.** The script does not phone home. No version-check pings, no usage stats.
- **No auto-update.** Use `git pull` if you want the latest version. Self-updating scripts are a supply chain risk.

---

## Code structure

- `sec-scan.sh` is a single bash file with ~10 numbered sections.
- Section 1: project root discovery.
- Section 2: system prereqs + early registry hijack abort.
- Section 3: worm IOC scan (filesystem + lockfile + workflows + git hooks + cron + shell-rc).
- Section 4: npm audit.
- Section 5: postinstall hook inventory.
- Section 6: .env security check.
- Section 7: git hygiene.
- Section 8: SSH key security.
- Section 9: npm registry + .npmrc.
- Section 10: summary + JSON sidecar + SHA-256 tamper-evidence + optional notify-email.

Helpers at the top of the file: `log`, `ok`, `warn`, `err`, `section`, `rep`, `rep_path`, `rep_redact`, `bump`, `do_action`, `quarantine`, `check_active_worm_procs`, `file_perms`, `ioc_format_ok`.

---

## Extending the scanner

To add a new framework mapping: update `docs/COMPLIANCE.md`.

To add new IOCs: edit the `COMPROMISED[]` array in `sec-scan.sh` (lines ~470–490) OR host a feed and point `SEC_SCAN_IOC_URL` at it.

To add a new persistence check: model after the git-hook scan at section 3.

To add a new framework's output field: extend the JSON sidecar near the end of the script.

Contributions: open a PR. CI runs `shellcheck` and `bash -n`.

---

_Reviewed for nyx-sec-scanner v2.2.0._
