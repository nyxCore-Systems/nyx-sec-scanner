#!/usr/bin/env bash
# ============================================================
# Dev Security Scanner — v2.0.0
#
# Purpose : Scan local developer machine for npm supply-chain
#           compromises (Shai-Hulud worm + recent IOCs), insecure
#           file permissions, anomalous postinstall hooks, and
#           shell/cron persistence. Auto-fix safe issues, quarantine
#           (NEVER delete) suspicious artifacts for manual review.
#
# Usage   : ./sec-scan.sh [--dry-run|--quarantine] [PROJECT_PATH]
#             --dry-run     report only, no modifications
#             --quarantine  move flagged artifacts to ~/.sec-scan-quarantine/
#                           (default mode also fixes safe permission issues)
#             PROJECT_PATH  npm project to audit (default: cwd or ancestors)
#
# Quarantine is non-destructive: files are MOVED to a timestamped
# directory under ~/.sec-scan-quarantine/. Nothing is deleted by this
# script. Review and remove manually after investigation.
# ============================================================

set -euo pipefail

VERSION="2.1.2"
SCAN_MODE="fix"           # fix | dry-run | quarantine
PROJECT_ARG=""
INCLUDE_IDENTITY=0        # 1 = log raw hostname/user/keyfile-names (opt-in)
VERBOSE=0
SKIP_LIVE_IOC=0
NOTIFY_EMAIL="${SEC_SCAN_NOTIFY_EMAIL:-}"
PURGE_ONLY=0

# ── Parse flags ──────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)            SCAN_MODE="dry-run"; shift ;;
    --quarantine)         SCAN_MODE="quarantine"; shift ;;
    --include-identity)   INCLUDE_IDENTITY=1; shift ;;
    --verbose|-v)         VERBOSE=1; shift ;;
    --no-live-ioc)        SKIP_LIVE_IOC=1; shift ;;
    --notify-email)       NOTIFY_EMAIL="$2"; shift 2 ;;
    --purge)              PURGE_ONLY=1; shift ;;
    --help|-h)
      sed -n '2,22p' "$0"
      exit 0 ;;
    -*)
      printf 'Unknown flag: %s\n' "$1" >&2
      exit 2 ;;
    *)
      PROJECT_ARG="$1"; shift ;;
  esac
done

# ── --purge (GDPR Art. 17 right to erasure) — handled before anything else
if [[ "$PURGE_ONLY" == "1" ]]; then
  REPORT_DIR_PURGE="${HOME}/.dev-security"
  QUAR_PURGE="${HOME}/.sec-scan-quarantine"
  printf 'Purge all reports + quarantine? Type YES to confirm: '
  read -r CONFIRM
  if [[ "$CONFIRM" == "YES" ]]; then
    rm -rf "$REPORT_DIR_PURGE"/scan-report_* "$QUAR_PURGE" 2>/dev/null || true
    printf 'Purged.\n'
    exit 0
  else
    printf 'Cancelled.\n'
    exit 1
  fi
fi

# ── Colors (real ANSI via $'…' so escapes work) ──────────────
RED=$'\033[0;31m'
ORANGE=$'\033[0;33m'
GREEN=$'\033[0;32m'
BLUE=$'\033[0;34m'
BOLD=$'\033[1m'
RESET=$'\033[0m'

# ── Configuration ────────────────────────────────────────────
REPORT_DIR="${HOME}/.dev-security"
QUARANTINE_DIR="${HOME}/.sec-scan-quarantine/$(date '+%Y%m%d-%H%M%S')"
TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
REPORT_FILE="${REPORT_DIR}/scan-report_${TIMESTAMP}.md"
MACHINE_NAME=$(hostname)
OS_TYPE=$(uname -s)

# ── Counters ─────────────────────────────────────────────────
ISSUES_FOUND=0
ISSUES_FIXED=0
MANUAL_ACTIONS=0
WORM_HITS=0
QUARANTINED=0
NONBLOCKING_ISSUES=0     # npm audit moderate/low — flagged but not blocking

# Per-section manual-action ledger. `section()` (below) automatically records
# how many MANUAL_ACTIONS each section contributed, so the summary footer can
# point the operator at the specific sections that need attention instead of
# emitting a bare count.
MA_SECTIONS=()
_MA_SECTION_NAME=""
_MA_BASELINE=0

bump() { eval "$1=\$((${1} + 1))"; }

# Validate IOC entry format at startup so malformed additions to the
# COMPROMISED array fail loudly instead of silently never matching.
# Accepts:  pkg@version    OR    @scope/pkg@version    (version may be *)
ioc_format_ok() {
  [[ "$1" =~ ^@?[a-zA-Z0-9_./-]+@([0-9.*+~^x]|[0-9]+\.[0-9.*x-]+|\*)$ ]]
}

# ── Helper functions ─────────────────────────────────────────
log()     { printf '%s[•]%s %s\n' "$BLUE"   "$RESET" "$*"; }
ok()      { printf '%s[✓]%s %s\n' "$GREEN"  "$RESET" "$*"; }
warn()    { printf '%s[!]%s %s\n' "$ORANGE" "$RESET" "$*"; }
err()     { printf '%s[✗]%s %s\n' "$RED"    "$RESET" "$*"; }
section() {
  # Close out the previous section's MANUAL_ACTIONS delta before announcing
  # the next. This lets the summary footer say "§ 4 npm Audit: 1, § 6 .env: 2"
  # without each callsite having to label itself.
  if [[ -n "$_MA_SECTION_NAME" ]]; then
    local _delta=$((MANUAL_ACTIONS - _MA_BASELINE))
    [[ $_delta -gt 0 ]] && MA_SECTIONS+=("§ ${_MA_SECTION_NAME} — ${_delta} item(s)")
  fi
  _MA_SECTION_NAME="$*"
  _MA_BASELINE=$MANUAL_ACTIONS
  printf '\n%s═══ %s ═══%s\n' "$BOLD" "$*" "$RESET"
}
rep()     { printf '%s\n' "$*" >> "$REPORT_FILE"; }

# Relativize a path to ~/ so the operator's username does not appear in the
# report (GDPR Art. 5(1)(c) minimization). Use this for every path that lands
# in the report — never raw "$path" / "$env_path" / "$keyfile".
rep_path() { printf '%s' "${1/#$HOME/~}"; }

# Redact long token-like substrings from arbitrary text before logging it to
# the report (GDPR Art. 32(1)(b) integrity + ISO A.8.12 DLP).
# Matches 20+-char runs of base64/hex/url-safe chars and replaces with [REDACTED].
rep_redact() { sed -E 's/[A-Za-z0-9_/+=.-]{20,}/[REDACTED]/g'; }

# Cross-platform stat for octal permission bits.
file_perms() {
  if [[ "$OS_TYPE" == "Darwin" ]]; then
    stat -f "%OLp" "$1" 2>/dev/null || echo "???"
  else
    stat -c "%a"  "$1" 2>/dev/null || echo "???"
  fi
}

# Honor mode flags for any mutating action. Returns 0 if action ran.
do_action() {
  local description=$1
  shift
  if [[ "$SCAN_MODE" == "dry-run" ]]; then
    warn "DRY-RUN: would $description"
    return 1
  fi
  "$@"
}

# Detect running processes that might still hold a quarantined file open.
# Quarantine via `mv` does NOT stop a process that has the file open via an
# existing fd — the inode survives unlink. Warning the operator is mandatory.
# Returns 0 (clean), 1 (suspicious process found).
check_active_worm_procs() {
  local procs
  procs=$(pgrep -fl 'shai|hulud|Shai-Hulud|data\.json|cloud\.json' 2>/dev/null || true)
  # Filter out this script's own process and our grep
  procs=$(printf '%s\n' "$procs" | grep -v "sec-scan.sh\|pgrep " || true)
  if [[ -n "$procs" ]]; then
    err "ACTIVE WORM-LIKE PROCESSES DETECTED — quarantine alone is insufficient:"
    printf '%s\n' "$procs" | sed 's/^/    /'
    rep "- ❌ **ACTIVE PROCESSES (review + manually kill before credential rotation):**"
    rep "  \`\`\`"
    printf '%s\n' "$procs" >> "$REPORT_FILE"
    rep "  \`\`\`"
    bump WORM_HITS
    bump MANUAL_ACTIONS
    return 1
  fi
  return 0
}

# Move a file/dir to the quarantine area (creates dir lazily).
quarantine() {
  local path=$1
  local why=$2
  if [[ "$SCAN_MODE" == "dry-run" ]]; then
    warn "DRY-RUN: would quarantine $path ($why)"
    return 1
  fi
  # WARN before move — a running worm process holding an open fd survives quarantine.
  check_active_worm_procs || warn "Worm processes may still be active; quarantine alone won't stop them."
  mkdir -p "$QUARANTINE_DIR"
  local dest="${QUARANTINE_DIR}/$(echo "$path" | tr '/' '_')"
  if mv "$path" "$dest" 2>/dev/null; then
    bump QUARANTINED
    err "Quarantined: $path → $dest ($why)"
    rep "- 🔒 **QUARANTINED:** \`${path}\` → \`${dest}\` (${why})"
    return 0
  else
    err "Failed to quarantine: $path"
    return 1
  fi
}

# ── Initialize report (mode 700 dir, 600 file) ───────────────
# Per GDPR Art. 32(2) + ISO 27001 A.8.24 + BSI ORP.4.A11 — reports contain
# pseudonymized PII and MUST NOT be world-readable. `install -d -m 700`
# is atomic and refuses to widen perms on an existing dir.
install -d -m 700 "$REPORT_DIR"

# Retention enforcement (GDPR Art. 5(1)(e) + ISO A.8.10 + BSI OPS.1.1.5).
# Reports older than RETENTION_DAYS (default 90) are auto-deleted at startup.
# Quarantine directories older than RETENTION_DAYS are also pruned.
RETENTION_DAYS="${SEC_SCAN_RETENTION_DAYS:-90}"
find "$REPORT_DIR" -maxdepth 1 -name "scan-report_*.md"     -mtime "+${RETENTION_DAYS}" -delete 2>/dev/null || true
find "$REPORT_DIR" -maxdepth 1 -name "scan-report_*.sha256" -mtime "+${RETENTION_DAYS}" -delete 2>/dev/null || true
find "$REPORT_DIR" -maxdepth 1 -name "scan-report_*.json"   -mtime "+${RETENTION_DAYS}" -delete 2>/dev/null || true
find "${HOME}/.sec-scan-quarantine" -maxdepth 1 -type d -mtime "+${RETENTION_DAYS}" \
  -exec rm -rf {} + 2>/dev/null || true

# Pseudonymized machine identifier (GDPR Art. 5(1)(c) data minimization +
# Art. 25 privacy by design). Raw hostname/user remain in shell variables for
# console output only — they are NEVER written to the report unless the
# operator explicitly opts in with --include-identity.
MACHINE_ID=$(printf '%s:%s' "$(hostname)" "$(whoami)" | shasum -a 256 | cut -c1-16)

{
  echo "# Dev Security Scan — Report"
  echo
  echo "| | |"
  echo "|---|---|"
  if [[ "${INCLUDE_IDENTITY:-0}" == "1" ]]; then
    echo "| **Machine** | ${MACHINE_NAME} (id ${MACHINE_ID}) |"
    echo "| **User** | $(whoami) |"
  else
    echo "| **Machine ID (pseudonym)** | ${MACHINE_ID} |"
    echo "| **User** | _suppressed (use --include-identity)_ |"
  fi
  echo "| **Date** | $(date '+%Y-%m-%dT%H:%M:%S%z') |"
  echo "| **OS** | $(uname -srm) |"
  echo "| **Scanner** | sec-scan.sh v${VERSION} |"
  echo "| **Mode** | ${SCAN_MODE} |"
  echo "| **Retention** | ${RETENTION_DAYS} days (auto-enforced) |"
  echo
  echo "## Privacy Notice"
  echo
  echo "This report is processed under **Art. 6(1)(f) GDPR** (legitimate interest:"
  echo "detection of supply-chain compromise on the data subject's own workstation)."
  echo "Personal data in this report: pseudonymized machine identifier, file paths"
  echo "(relative to \`\$HOME\`), optional raw identifiers when \`--include-identity\` is set."
  echo "Retention: ${RETENTION_DAYS} days (older reports auto-deleted on next scan)."
  echo "Right to erasure (Art. 17): \`sec-scan.sh --purge\`."
  echo "Report integrity: SHA-256 fingerprint appended at end + sidecar \`.sha256\` file."
  echo
  echo "---"
  echo
} > "$REPORT_FILE"
# Confidentiality (GDPR Art. 32(2) + ISO A.8.24)
chmod 600 "$REPORT_FILE"

# ============================================================
printf '\n%s╔════════════════════════════════════════╗%s\n' "$BOLD" "$RESET"
printf '%s║   Dev Security Scanner v%-15s║%s\n' "$BOLD" "$VERSION" "$RESET"
printf '%s║   Mode: %-31s║%s\n' "$BOLD" "$SCAN_MODE" "$RESET"
printf '%s╚════════════════════════════════════════╝%s\n\n' "$BOLD" "$RESET"

# ============================================================
section "1 · Locate project root"
# ============================================================

PROJECT_ROOT=""
SEARCH_DIR="${PROJECT_ARG:-$(pwd)}"
if [[ -n "$PROJECT_ARG" ]] && [[ ! -d "$PROJECT_ARG" ]]; then
  err "PROJECT_PATH does not exist: $PROJECT_ARG"
  exit 2
fi

for _ in 0 1 2 3 4; do
  if [[ -f "${SEARCH_DIR}/package.json" ]]; then
    PROJECT_ROOT="$SEARCH_DIR"
    break
  fi
  parent=$(dirname "$SEARCH_DIR")
  [[ "$parent" == "$SEARCH_DIR" ]] && break    # hit /
  SEARCH_DIR="$parent"
done

rep "## 1. Project directory"
rep ""

if [[ -z "$PROJECT_ROOT" ]]; then
  warn "No package.json found — npm-specific checks will be skipped."
  rep "- No \`package.json\` found in \`$(pwd)\` or ancestors. npm checks skipped."
  rep ""
  NPM_AVAILABLE=false
else
  ok "Project root: $PROJECT_ROOT"
  PKG_INFO="unknown"
  if command -v jq >/dev/null 2>&1; then
    PKG_INFO=$(jq -r '.name + " v" + .version' "${PROJECT_ROOT}/package.json" 2>/dev/null || echo "unknown")
  fi
  log "package.json: $PKG_INFO"
  rep "- **Path:** \`$(rep_path "${PROJECT_ROOT}")\`"
  rep "- **Package:** ${PKG_INFO}"
  rep ""
  NPM_AVAILABLE=true
fi

# ============================================================
section "2 · System prerequisites"
# ============================================================

rep "## 2. System prerequisites"
rep ""
rep "| Tool | Version | Status |"
rep "|------|---------|--------|"

check_tool() {
  local tool=$1 cmd=$2 version
  if command -v "$tool" >/dev/null 2>&1; then
    version=$(eval "$cmd" 2>/dev/null | head -1 || echo "unknown")
    ok "${tool}: ${version}"
    rep "| \`${tool}\` | ${version} | ✅ |"
  else
    warn "${tool} not found"
    rep "| \`${tool}\` | — | ❌ not installed |"
  fi
}

check_tool "node"   "node --version"
check_tool "npm"    "npm --version"
check_tool "git"    "git --version"
check_tool "docker" "docker --version"
check_tool "jq"     "jq --version"
rep ""

# ── 2b · Early registry hijack check (BLOCKER per Nemesis) ──
# Must run BEFORE any `npm audit fix` or install command, otherwise a
# hijacked registry would silently feed us backdoored "fixes".
if command -v npm >/dev/null 2>&1; then
  EARLY_REGISTRY=$(npm config get registry 2>/dev/null || echo "unknown")
  if [[ "$EARLY_REGISTRY" != "https://registry.npmjs.org/" ]]; then
    err "ABORT: active npm registry is '${EARLY_REGISTRY}' — not the default."
    err "An attacker-controlled registry would poison any auto-fix step."
    err "Inspect with: npm config get registry"
    err "Reset with:   npm config set registry https://registry.npmjs.org/"
    rep "## ⛔ ABORTED — non-default npm registry"
    rep ""
    rep "Active registry: \`${EARLY_REGISTRY}\`"
    rep ""
    rep "Refusing to continue. A non-default registry could be a hijack;"
    rep "running \`npm audit fix\` against it would pull backdoored \"fixes\"."
    rep "If this is an intended private mirror, set env \`SEC_SCAN_ALLOW_REGISTRY=1\` and rerun."
    if [[ "${SEC_SCAN_ALLOW_REGISTRY:-0}" != "1" ]]; then
      exit 3
    fi
    warn "SEC_SCAN_ALLOW_REGISTRY=1 set — continuing against caller's wish for safety."
    rep "_Continuation forced by \`SEC_SCAN_ALLOW_REGISTRY=1\`._"
    rep ""
  else
    ok "Registry verified: ${EARLY_REGISTRY}"
    rep "- ✅ Registry verified: \`${EARLY_REGISTRY}\`"
    rep ""
  fi
fi

# ============================================================
section "3 · Worm / supply-chain IOC scan"
# ============================================================
#
# Indicators of Compromise from the 2025 npm supply-chain incidents:
#   - "Shai-Hulud" self-replicating worm (Sep 2025) — propagates via
#     compromised postinstall hooks, exfiltrates secrets, creates a
#     public GitHub repo named "Shai-Hulud" with the loot.
#   - Chalk/debug/ansi-styles compromise (Sep 2025) — specific tainted
#     versions push payloads to ${HOME}/Shai-Hulud-*, install a
#     malicious workflow under .github/workflows/.
#
# Keep this section's IOC arrays current. New compromises happen weekly;
# the canonical sources are npm security advisories and Socket.dev /
# JFrog research. The pattern matches below are conservative — they will
# yield false positives. A hit means INVESTIGATE, not "you are infected".

rep "## 3. Worm / supply-chain IOC scan"
rep ""

# ── 3a · Filesystem IOCs in $HOME ────────────────────────────
log "Scanning \$HOME for worm artifacts..."

SHAI_PATTERNS=(
  "${HOME}/Shai-Hulud"
  "${HOME}/Shai-Hulud-migration"
  "${HOME}/Shai-Hulud.json"
  "${HOME}/.shai-hulud"
  "${HOME}/data.json"           # often dropped by exfil payload
  "${HOME}/cloud.json"          # observed in nx incident
)

HOME_HITS=()
for p in "${SHAI_PATTERNS[@]}"; do
  if [[ -e "$p" ]]; then
    HOME_HITS+=("$p")
    bump WORM_HITS
    err "WORM IOC: $p exists"
    if [[ "$SCAN_MODE" == "quarantine" ]]; then
      quarantine "$p" "Shai-Hulud filesystem IOC"
    else
      rep "- ❌ **WORM IOC:** \`${p}\` (re-run with \`--quarantine\` to move it)"
      bump MANUAL_ACTIONS
    fi
  fi
done

# Recursively look for the worm's dropped bundle (limited depth — avoid
# scanning the entire homedir which is slow and noisy).
log "Scanning shallow \$HOME for bundle.js / index.js droppers..."
SUSPECT_BUNDLES=$(find "${HOME}" -maxdepth 3 -type f \
  \( -name "bundle.js" -o -name "shai*.js" \) \
  -not -path "${HOME}/.npm/*" \
  -not -path "${HOME}/Library/Caches/*" \
  -not -path "${HOME}/.cache/*" \
  -not -path "${HOME}/node_modules/*" \
  2>/dev/null || true)

if [[ -n "$SUSPECT_BUNDLES" ]]; then
  warn "Suspicious bundles found in \$HOME — review manually:"
  while IFS= read -r b; do
    [[ -z "$b" ]] && continue
    rep "- ⚠️ Suspicious file: \`${b}\` (verify origin — known dropper name)"
    printf '    %s\n' "$b"
    bump MANUAL_ACTIONS
  done <<< "$SUSPECT_BUNDLES"
else
  ok "No bundle.js / shai*.js droppers in shallow \$HOME"
fi
rep ""

# ── 3a-ext · staging payloads in /tmp + macOS Application Support ──
log "Scanning /tmp for staging scripts..."
TMP_SCRIPTS=$(find /tmp -maxdepth 1 -type f -name "*.sh" -newer /tmp 2>/dev/null \
              | grep -v '^/tmp/\.' || true)
if [[ -n "$TMP_SCRIPTS" ]]; then
  warn "Recent /tmp/*.sh files (worm payloads often stage here):"
  while IFS= read -r s; do
    [[ -z "$s" ]] && continue
    printf '    %s\n' "$s"
    rep "- ⚠️ Recent staging script: \`${s}\` — review (worms drop payloads in /tmp)"
    bump MANUAL_ACTIONS
  done <<< "$TMP_SCRIPTS"
else
  ok "No recent /tmp/*.sh staging scripts"
fi

if [[ "$OS_TYPE" == "Darwin" ]] && [[ -d "${HOME}/Library/Application Support" ]]; then
  log "Scanning ~/Library/Application Support for unfamiliar UUID-named dirs..."
  UUID_DIRS=$(find "${HOME}/Library/Application Support" -maxdepth 1 -type d \
                -regex '.*/[0-9A-Fa-f]\{8\}-[0-9A-Fa-f]\{4\}.*' 2>/dev/null || true)
  if [[ -n "$UUID_DIRS" ]]; then
    warn "UUID-named directories in Application Support (worms sometimes drop here):"
    while IFS= read -r d; do
      [[ -z "$d" ]] && continue
      printf '    %s\n' "$d"
      rep "- ⚠️ UUID-shaped dir in \`~/Library/Application Support\`: \`$(basename "$d")\` — verify origin"
      bump MANUAL_ACTIONS
    done <<< "$UUID_DIRS"
  fi
fi

# ── 3a-git · git hook persistence (per-repo + global) ────────
log "Scanning git repos under \$HOME for tampered hooks..."

GLOBAL_HOOKS=$(git config --global core.hooksPath 2>/dev/null || echo "")
if [[ -n "$GLOBAL_HOOKS" ]]; then
  warn "Global git hooks path is set: $GLOBAL_HOOKS"
  rep "- ⚠️ Git global \`core.hooksPath\` = \`${GLOBAL_HOOKS}\` — every git op runs hooks from here. Verify origin."
  bump MANUAL_ACTIONS
  bump WORM_HITS
  # Scan that directory for our flag patterns
  if [[ -d "$GLOBAL_HOOKS" ]]; then
    SUSPECT_GLOBAL_HOOKS=$(grep -rlE '(curl|wget).*sh\b|shai|hulud|node_modules/\.bin' "$GLOBAL_HOOKS" 2>/dev/null || true)
    if [[ -n "$SUSPECT_GLOBAL_HOOKS" ]]; then
      err "Hooks at $GLOBAL_HOOKS contain suspicious patterns!"
      while IFS= read -r h; do
        [[ -z "$h" ]] && continue
        rep "- ❌ Suspicious global hook: \`${h}\`"
      done <<< "$SUSPECT_GLOBAL_HOOKS"
    fi
  fi
fi

# Cheap per-repo hook check: only post-commit + post-checkout + pre-push under
# the first 4 levels of $HOME (deeper repos are uncommon for active dev).
REPO_HOOK_HITS=$(find "${HOME}" -maxdepth 4 -type f \
  \( -name "post-commit" -o -name "post-checkout" -o -name "pre-push" \) \
  -path "*/.git/hooks/*" \
  -not -path "${HOME}/Library/*" \
  2>/dev/null \
  | xargs -I {} grep -lE '(curl|wget).*sh\b|shai|hulud' {} 2>/dev/null || true)

if [[ -n "$REPO_HOOK_HITS" ]]; then
  err "Tampered git hooks in repos under \$HOME:"
  while IFS= read -r h; do
    [[ -z "$h" ]] && continue
    err "  $h"
    rep "- ❌ **TAMPERED HOOK:** \`${h}\` — review or revert via \`git checkout HEAD -- $(dirname "$h")\`"
    bump WORM_HITS
    bump MANUAL_ACTIONS
  done <<< "$REPO_HOOK_HITS"
else
  ok "No tampered git hooks in shallow \$HOME repos"
fi
rep ""

# ── 3b · Compromised npm package versions ────────────────────
#
# This list is a STARTING POINT. Update from canonical IOC feeds when
# new compromises are disclosed. Format: "name@version-spec".
# The version spec is a glob — "*" matches all; "5.6.1" matches exact.

COMPROMISED=(
  # Shai-Hulud Sep 2025 wave (sample — extend from canonical IOC list)
  "@ctrl/tinycolor@4.1.1"
  "@ctrl/tinycolor@4.1.2"
  # NOTE: @nativescript-community/ui-mobile-base wildcard was too broad — it is a
  # legitimate package whose entire version history would fire false positives.
  # Add specific tainted versions here when canonical sources publish them.
  "ngx-bootstrap@18.1.4"
  "ngx-color@10.0.1"
  "ngx-toastr@19.0.0"
  "gauntletjs@*"
  # chalk/debug compromise Sep 2025 — historical, kept for completeness
  "chalk@5.6.1"
  "debug@4.4.2"
  "ansi-styles@6.2.2"
  "color-convert@3.1.1"
  "color-name@2.0.1"
  "is-arrayish@0.3.3"
  "error-ex@1.3.3"
  "supports-color@10.2.1"
  # nx malicious release (Aug 2025)
  "nx@21.5.0"
  "nx@20.9.0"
  "@nx/core@21.5.0"
)

# Optional live IOC fetch. Set SEC_SCAN_IOC_URL to a URL that returns one
# IOC per line in `name@version` or `@scope/name@version` format. The static
# COMPROMISED list above remains the floor — even if the fetch fails, you
# still scan against the hardcoded baseline. Suggested sources to host such
# a feed (or generate from): Socket.dev research, OpenSSF Package Analysis,
# npm registry security advisories.
if [[ -n "${SEC_SCAN_IOC_URL:-}" && "${SKIP_LIVE_IOC:-0}" != "1" ]]; then
  # ISO 27001 A.8.20 (network security) + A.5.7 (threat intelligence provenance)
  # + NIS2 Art. 21(2)(g) (supply chain). Enforce HTTPS + TLS 1.2 minimum.
  # Optionally verify content integrity against a known SHA-256 manifest set
  # in SEC_SCAN_IOC_SHA256 — defends against silent feed-poisoning by an
  # attacker with MITM position.
  if [[ ! "$SEC_SCAN_IOC_URL" =~ ^https:// ]]; then
    err "SEC_SCAN_IOC_URL must use HTTPS (got: ${SEC_SCAN_IOC_URL})"
    rep "- ❌ **REFUSED:** non-HTTPS IOC feed URL — would expose threat intel to MITM"
    bump MANUAL_ACTIONS
  else
    log "Fetching live IOCs from ${SEC_SCAN_IOC_URL}..."
    LIVE_IOCS=$(curl -sf --max-time 5 --proto '=https' --tlsv1.2 \
      "$SEC_SCAN_IOC_URL" 2>/dev/null || true)
    if [[ -n "$LIVE_IOCS" ]]; then
      # Optional integrity verification — operator pins the expected SHA-256.
      if [[ -n "${SEC_SCAN_IOC_SHA256:-}" ]]; then
        ACTUAL_HASH=$(printf '%s' "$LIVE_IOCS" | shasum -a 256 | cut -d' ' -f1)
        if [[ "$ACTUAL_HASH" != "$SEC_SCAN_IOC_SHA256" ]]; then
          err "IOC feed integrity check FAILED"
          err "  expected: $SEC_SCAN_IOC_SHA256"
          err "  actual:   $ACTUAL_HASH"
          rep "- ❌ **IOC feed integrity check FAILED** — refused, using static list only"
          bump WORM_HITS
          bump MANUAL_ACTIONS
          LIVE_IOCS=""
        else
          ok "IOC feed integrity verified (SHA-256 match)"
        fi
      fi
      if [[ -n "$LIVE_IOCS" ]]; then
        LIVE_COUNT=0
        while IFS= read -r ioc; do
          ioc=$(printf '%s' "$ioc" | tr -d '[:space:]')
          [[ -z "$ioc" || "$ioc" == \#* ]] && continue
          if ioc_format_ok "$ioc"; then
            COMPROMISED+=("$ioc")
            LIVE_COUNT=$((LIVE_COUNT + 1))
          else
            warn "Skipping malformed live IOC entry: $ioc"
          fi
        done <<< "$LIVE_IOCS"
        ok "Merged ${LIVE_COUNT} live IOC entries"
        rep "- ✅ Live IOC fetch merged ${LIVE_COUNT} entries from \`${SEC_SCAN_IOC_URL}\`"
      fi
    else
      warn "Live IOC fetch failed — falling back to static list"
      rep "- ⚠️ Live IOC fetch failed (offline / 4xx / timeout); using static list only"
    fi
  fi
fi

# Validate every IOC entry at startup so a typo in COMPROMISED doesn't silently
# never match (Nemesis MINOR #6).
for ioc in "${COMPROMISED[@]}"; do
  if ! ioc_format_ok "$ioc"; then
    err "Malformed IOC entry in COMPROMISED[]: '${ioc}'"
    err "Expected: pkg@version OR @scope/pkg@version (version may be *)"
    exit 4
  fi
done

if [[ "$NPM_AVAILABLE" == true ]] && [[ -f "${PROJECT_ROOT}/package-lock.json" ]]; then
  log "Cross-checking package-lock.json against ${#COMPROMISED[@]} known IOC entries..."

  LOCK_HITS=$(node -e '
    const fs = require("fs");
    const lock = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    const iocs = process.argv.slice(2).map(s => {
      const [n, v] = s.split("@").length === 3
        ? [s.slice(0, s.lastIndexOf("@")), s.split("@").pop()]
        : ["@" + s.split("@")[1], s.split("@")[2]];
      return { name: n, version: v };
    });
    const pkgs = lock.packages || {};
    const hits = [];
    for (const [path, meta] of Object.entries(pkgs)) {
      const name = (path.replace(/^node_modules\//, "") || "").split("/node_modules/").pop();
      if (!name) continue;
      const version = meta.version || "";
      for (const ioc of iocs) {
        if (ioc.name === name && (ioc.version === "*" || ioc.version === version)) {
          hits.push(`${name}@${version} (at ${path})`);
        }
      }
    }
    if (hits.length === 0) process.exit(0);
    for (const h of hits) console.log(h);
    process.exit(0);
  ' "${PROJECT_ROOT}/package-lock.json" "${COMPROMISED[@]}" 2>/dev/null || true)

  if [[ -n "$LOCK_HITS" ]]; then
    err "COMPROMISED PACKAGE DETECTED in lockfile:"
    while IFS= read -r h; do
      [[ -z "$h" ]] && continue
      err "  $h"
      rep "- ❌ **COMPROMISED:** \`${h}\`"
      bump WORM_HITS
      bump MANUAL_ACTIONS
    done <<< "$LOCK_HITS"
    rep ""
    rep "**Required action:** pin to a known-good version, delete \`node_modules\` + \`package-lock.json\`, re-install. Then ROTATE every secret accessible from the dev machine (npm tokens, AWS keys, .env values) — the worm exfiltrates whatever it can read."
    rep ""
  else
    ok "No known-compromised package versions in lockfile."
    rep "- ✅ Lockfile clean of known IOCs (${#COMPROMISED[@]} entries checked)."
  fi
else
  rep "- _Lockfile IOC check skipped — no package-lock.json._"
fi
rep ""

# ── 3c · Malicious GitHub workflow ──────────────────────────
if [[ "$NPM_AVAILABLE" == true ]] && [[ -d "${PROJECT_ROOT}/.github/workflows" ]]; then
  SHAI_WF=$(find "${PROJECT_ROOT}/.github/workflows" -type f \
    \( -iname "*shai*" -o -iname "*hulud*" \) 2>/dev/null || true)
  if [[ -n "$SHAI_WF" ]]; then
    err "MALICIOUS WORKFLOW detected:"
    while IFS= read -r w; do
      [[ -z "$w" ]] && continue
      err "  $w"
      rep "- ❌ **MALICIOUS WORKFLOW:** \`${w}\`"
      bump WORM_HITS
      if [[ "$SCAN_MODE" == "quarantine" ]]; then
        quarantine "$w" "Shai-Hulud workflow"
      else
        bump MANUAL_ACTIONS
      fi
    done <<< "$SHAI_WF"
  else
    ok "No Shai-Hulud workflows in .github/workflows/"
    rep "- ✅ No \`*shai*\` / \`*hulud*\` workflows."
  fi
else
  rep "- _GitHub workflow check skipped — no .github/workflows/._"
fi
rep ""

# ── 3d · Shell-rc persistence ────────────────────────────────
log "Inspecting shell rc files for unexpected hooks..."

SHELL_RC_FILES=(".bashrc" ".bash_profile" ".zshrc" ".zprofile" ".profile")
RC_FLAGS=("curl.*sh" "wget.*sh" "shai" "hulud" "data\\.json" "exfil")

for rc in "${SHELL_RC_FILES[@]}"; do
  path="${HOME}/${rc}"
  [[ -f "$path" ]] || continue
  for pat in "${RC_FLAGS[@]}"; do
    if grep -inE "$pat" "$path" >/dev/null 2>&1; then
      MATCHES=$(grep -inE "$pat" "$path" 2>/dev/null | head -3 || true)
      warn "Suspicious pattern '$pat' in $path:"
      printf '%s\n' "$MATCHES" | sed 's/^/    /'
      rep "- ⚠️ Pattern \`${pat}\` in \`${rc}\` — review (long tokens redacted):"
      rep "  \`\`\`"
      # Redact 20+-char token-like substrings (GDPR Art. 32(1)(b) + ISO A.8.12 DLP)
      printf '%s\n' "$MATCHES" | rep_redact >> "$REPORT_FILE"
      rep "  \`\`\`"
      bump MANUAL_ACTIONS
    fi
  done
done
rep ""

# ── 3e · Cron / launchd persistence ──────────────────────────
log "Checking scheduled-task persistence (crontab + launchd)..."

if command -v crontab >/dev/null 2>&1; then
  CRON_CONTENT=$(crontab -l 2>/dev/null || true)
  if [[ -n "$CRON_CONTENT" ]]; then
    # GDPR Art. 5(1)(c) data minimization — do NOT log verbatim crontab.
    # Crontab content may contain personal data (paths, env vars, schedules
    # revealing workflow patterns). Log count + verdict; only the suspicious
    # MATCHING lines are surfaced (redacted) for the operator to investigate.
    CRON_LINES=$(printf '%s\n' "$CRON_CONTENT" | grep -cvE '^[[:space:]]*(#|$)' || true)
    rep "- ℹ️ Crontab: ${CRON_LINES} active entry(ies) (content not logged per privacy policy)"
    if echo "$CRON_CONTENT" | grep -iE "(curl|wget).*sh\b|shai|hulud|/tmp/.*\.sh" >/dev/null; then
      err "Suspicious cron entry — review crontab manually"
      MATCHING_CRON=$(printf '%s\n' "$CRON_CONTENT" | grep -iE "(curl|wget).*sh\b|shai|hulud|/tmp/.*\.sh" | rep_redact)
      rep "- ❌ **SUSPICIOUS PATTERN** in crontab (long tokens redacted):"
      rep "  \`\`\`"
      printf '%s\n' "$MATCHING_CRON" >> "$REPORT_FILE"
      rep "  \`\`\`"
      bump MANUAL_ACTIONS
      bump WORM_HITS
    else
      ok "Crontab looks clean (no curl-piped-sh / shai patterns)"
    fi
  else
    ok "No crontab entries"
    rep "- ✅ No crontab entries"
  fi
fi

if [[ "$OS_TYPE" == "Darwin" ]] && [[ -d "${HOME}/Library/LaunchAgents" ]]; then
  AGENT_COUNT=$(find "${HOME}/Library/LaunchAgents" -maxdepth 1 -type f -name "*.plist" 2>/dev/null | wc -l | tr -d ' ')
  log "User LaunchAgents: ${AGENT_COUNT}"
  rep "- macOS LaunchAgents count: \`${AGENT_COUNT}\` (manually inspect \`~/Library/LaunchAgents/\` for unfamiliar plists)"
fi
rep ""

# ============================================================
section "4 · npm Audit"
# ============================================================

rep "## 4. npm Audit"
rep ""

# Single Node parser instead of 4 — DRY.
parse_audit() {
  node -e '
    const fs = require("fs");
    let data = "";
    process.stdin.on("data", c => data += c);
    process.stdin.on("end", () => {
      let r;
      try { r = JSON.parse(data); } catch { console.log("0 0 0 0"); return; }
      const v = (r.metadata && r.metadata.vulnerabilities) || {};
      console.log([v.critical||0, v.high||0, v.moderate||0, v.low||0].join(" "));
    });
  ' 2>/dev/null
}

if [[ "$NPM_AVAILABLE" == true ]]; then
  cd "$PROJECT_ROOT"

  if [[ ! -d "node_modules" ]]; then
    warn "node_modules missing — run npm ci first."
    rep "**⚠️ node_modules not found** — audit skipped."
    bump ISSUES_FOUND
  else
    log "Running npm audit..."
    AUDIT_JSON=$(npm audit --json 2>/dev/null || true)
    read -r CRITICAL HIGH MODERATE LOW < <(printf '%s' "$AUDIT_JSON" | parse_audit)

    rep "### Result before fix"
    rep ""
    rep "| Severity | Count |"
    rep "|---------|-------|"
    rep "| 🔴 Critical | ${CRITICAL} |"
    rep "| 🟠 High     | ${HIGH} |"
    rep "| 🟡 Moderate | ${MODERATE} |"
    rep "| 🔵 Low      | ${LOW} |"
    rep ""

    BLOCKING=$((CRITICAL + HIGH))
    NONBLOCKING_ISSUES=$((NONBLOCKING_ISSUES + MODERATE + LOW))   # tally regardless of branch
    if [[ "$BLOCKING" -gt 0 ]]; then
      err "${CRITICAL} critical + ${HIGH} high vulnerabilities."
      [[ "$((MODERATE + LOW))" -gt 0 ]] && warn "Plus ${MODERATE} moderate + ${LOW} low (non-blocking, surfaced in summary)."
      bump ISSUES_FOUND
      ISSUES_FOUND=$((ISSUES_FOUND + BLOCKING - 1))   # already bumped once

      if [[ "$SCAN_MODE" != "dry-run" ]]; then
        log "Attempting safe auto-fix (npm audit fix --omit=dev)..."
        if npm audit fix --omit=dev 2>&1 | tee /tmp/audit-fix-output.txt >/dev/null; then
          read -r CA HA _ _ < <(npm audit --json 2>/dev/null | parse_audit)
          REMAINING=$((CA + HA))
          rep "### Result after auto-fix"
          rep ""
          rep "| Severity | Before | After |"
          rep "|---------|--------|-------|"
          rep "| 🔴 Critical | ${CRITICAL} | ${CA} |"
          rep "| 🟠 High     | ${HIGH} | ${HA} |"
          rep ""
          if [[ "$REMAINING" -gt 0 ]]; then
            warn "${REMAINING} not auto-fixable — see \`npm audit\`. Consider \`npm audit fix --force\` after reviewing breaking changes."
            rep "**⚠️ ${REMAINING} vulnerability(ies) need manual review.**"
            bump MANUAL_ACTIONS
          else
            ok "All high/critical auto-fixed."
            rep "✅ All high/critical fixed."
            ISSUES_FIXED=$((ISSUES_FIXED + BLOCKING))
          fi
        else
          err "npm audit fix failed — see /tmp/audit-fix-output.txt"
          rep "**❌ auto-fix failed.** Manual review required."
          # Embed the last 30 lines of npm's own output so the operator can
          # diagnose without leaving the report (peer-dep conflicts, --force
          # required, registry unreachable, etc.). Redact long token-like
          # substrings to keep accidental auth headers out of the report.
          if [[ -s /tmp/audit-fix-output.txt ]]; then
            rep ""
            rep "<details><summary>npm audit fix output — last 30 lines (redacted)</summary>"
            rep ""
            rep '```'
            tail -n 30 /tmp/audit-fix-output.txt | rep_redact >> "$REPORT_FILE"
            rep '```'
            rep ""
            rep "</details>"
          fi
          bump MANUAL_ACTIONS
        fi
      else
        warn "DRY-RUN: skipping auto-fix"
      fi
    elif [[ "$((MODERATE + LOW))" -gt 0 ]]; then
      warn "${MODERATE} moderate + ${LOW} low (non-blocking)"
      rep "**ℹ️ Only moderate/low vulnerabilities** — clean up on next major update."
    else
      ok "No vulnerabilities found."
      rep "✅ **No vulnerabilities.**"
    fi
    rep ""
  fi
else
  rep "_npm audit skipped — no project directory._"
  rep ""
fi

# ============================================================
section "5 · Postinstall hook inventory"
# ============================================================

rep "## 5. Postinstall hook inventory"
rep ""

# A whitelist is fragile — instead we list hooks and let the operator
# eyeball them. Known-good prefixes are marked, everything else is
# YELLOW (review) rather than RED. The actual red flag is "package
# added between two commits with a brand-new install hook" — that
# requires diffing, out of scope for a one-shot scan.

if [[ "$NPM_AVAILABLE" == true ]] && [[ -f "${PROJECT_ROOT}/package-lock.json" ]]; then
  cd "$PROJECT_ROOT"
  log "Listing packages with install / preinstall / postinstall hooks..."

  HOOK_OUTPUT=$(node -e '
    const fs = require("fs");
    const lock = JSON.parse(fs.readFileSync("./package-lock.json", "utf8"));
    const pkgs = lock.packages || {};
    const out = [];
    for (const [path, meta] of Object.entries(pkgs)) {
      const s = meta.scripts || {};
      const ks = ["install","preinstall","postinstall"].filter(k => s[k]);
      if (!ks.length) continue;
      const name = (path.replace(/^node_modules\//, "") || "(root)");
      const cmd = ks.map(k => `${k}:${(s[k]||"").slice(0,60)}`).join("|");
      out.push(`${name}\t${cmd}`);
    }
    out.sort();
    console.log(out.length);
    out.forEach(l => console.log(l));
  ' 2>/dev/null || echo "0")

  HOOK_TOTAL=$(echo "$HOOK_OUTPUT" | head -1)
  log "Packages with install hooks: ${HOOK_TOTAL}"

  rep "Packages with \`install\`/\`preinstall\`/\`postinstall\` hooks: **${HOOK_TOTAL}**"
  rep ""
  rep "| Package | Hook → command (first 60 chars) | Verdict |"
  rep "|---------|---------------------------------|---------|"

  # Conservative known-legitimate list (anchored to package names with @ or word boundary).
  KNOWN_RE='^(@prisma/|prisma$|esbuild$|sharp$|@next/|next$|husky$|electron$|canvas$|node-gyp$|bcrypt$|argon2$|sqlite3$|better-sqlite3$|node-sass$|fsevents$|@swc/|@parcel/|@biomejs/|deasync$|fibers$|nodemon$|node-pre-gyp$|cypress$|playwright(-core)?$|puppeteer.*$|@nrwl/|@nx/|nx$|robotjs$|sodium-native$|node-cron$|onnxruntime.*$|@tensorflow/|@aws-sdk/util-utf8-node$)'

  echo "$HOOK_OUTPUT" | tail -n +2 | while IFS=$'\t' read -r pkg cmd; do
    pkg=${pkg//\`/}; cmd=${cmd//\`/}
    [[ -z "$pkg" ]] && continue
    if echo "$pkg" | grep -qE "$KNOWN_RE"; then
      verdict="🟢 known"
    else
      verdict="🟡 review"
    fi
    printf '| `%s` | `%s` | %s |\n' "$pkg" "$cmd" "$verdict" >> "$REPORT_FILE"
  done

  rep ""
else
  rep "_Skipped — no package-lock.json._"
  rep ""
fi

# ============================================================
section "6 · .env security check"
# ============================================================

rep "## 6. .env security check"
rep ""

check_env_file() {
  local env_path=$1 label=$2
  [[ -f "$env_path" ]] || return 0

  rep "### \`${label}\`"
  rep ""

  local perms
  perms=$(file_perms "$env_path")
  if [[ "$perms" == "600" || "$perms" == "400" ]]; then
    ok "${label}: permissions OK (${perms})"
    rep "- ✅ Permissions \`${perms}\` (secure)"
  else
    warn "${label}: insecure permissions (${perms})"
    if do_action "chmod 600 $env_path" chmod 600 "$env_path"; then
      rep "- 🔧 Permissions \`${perms}\` → \`600\`"
      bump ISSUES_FIXED
    fi
    bump ISSUES_FOUND
  fi

  # Git index check
  if git -C "$(dirname "$env_path")" ls-files --error-unmatch "$env_path" >/dev/null 2>&1; then
    err "${label} is tracked by Git — exfil risk!"
    rep "- ❌ **CRITICAL:** tracked by Git → \`git rm --cached '${env_path}'\`"
    bump ISSUES_FOUND
    bump MANUAL_ACTIONS
  else
    rep "- ✅ Not tracked by Git"
  fi

  # Production-secret pattern probes (generic — no project-specific hostnames)
  local prod_patterns=(
    '_LIVE_'                       # *_LIVE_*
    'sk_live_'                     # Stripe live secret keys
    'pk_live_'                     # Stripe live publishable keys
    'AKIA[0-9A-Z]{16}'             # AWS access key ID
    'ASIA[0-9A-Z]{16}'             # AWS temporary credential
    '[0-9a-f]{64}'                 # 256-bit hex secret (vague — high false positive)
    'ghp_[0-9A-Za-z]{20,}'         # GitHub PAT (classic)
    'github_pat_[0-9A-Za-z_]{20,}' # GitHub PAT (fine-grained)
    'glpat-[0-9A-Za-z_-]{20,}'     # GitLab PAT
    'npm_[0-9A-Za-z]{36}'          # npm auth token
  )
  local hits=0
  for p in "${prod_patterns[@]}"; do
    if grep -qE "$p" "$env_path" 2>/dev/null; then
      hits=$((hits + 1))
    fi
  done
  if [[ "$hits" -gt 0 ]]; then
    warn "${label}: ${hits} production-secret-shaped pattern(s) — verify"
    rep "- ⚠️ **${hits} production-secret pattern(s)** detected. Verify whether these are real production credentials. Prefer 1Password CLI / direnv / Infisical over plaintext."
    bump MANUAL_ACTIONS
  else
    rep "- ✅ No production-secret patterns detected"
  fi
  rep ""
}

if [[ "$NPM_AVAILABLE" == true ]]; then
  for f in .env .env.local .env.development .env.development.local .env.production .env.production.local; do
    check_env_file "${PROJECT_ROOT}/${f}" "${f}"
  done
fi

# Home-dir .env is always wrong
if [[ -f "${HOME}/.env" ]]; then
  err "Stray ${HOME}/.env — secrets in \$HOME is a red flag."
  rep "### ⚠️ \`~/.env\` found — secrets do not belong in \$HOME"
  rep ""
  if [[ "$SCAN_MODE" == "quarantine" ]]; then
    quarantine "${HOME}/.env" "stray .env in home directory"
  else
    bump MANUAL_ACTIONS
  fi
  bump ISSUES_FOUND
fi
rep ""

# ============================================================
section "7 · Git hygiene"
# ============================================================

rep "## 7. Git hygiene"
rep ""

if [[ "$NPM_AVAILABLE" == true ]]; then
  cd "$PROJECT_ROOT"

  if [[ -f ".gitignore" ]]; then
    if grep -qE '^\.env(\..*)?$|^\*\.env|^\.env\*' .gitignore 2>/dev/null; then
      ok ".env covered by .gitignore"
      rep "- ✅ \`.env\` patterns in \`.gitignore\`"
    else
      warn ".env NOT in .gitignore"
      if do_action "append .env patterns to .gitignore" \
           sh -c 'printf "\n# Added by sec-scan.sh\n.env\n.env.local\n.env.*.local\n" >> .gitignore'; then
        rep "- 🔧 \`.env\` patterns appended to \`.gitignore\`"
        bump ISSUES_FIXED
      fi
      bump ISSUES_FOUND
    fi
  else
    warn "No .gitignore"
    rep "- ❌ No \`.gitignore\` — secret-leak risk"
    bump MANUAL_ACTIONS
    bump ISSUES_FOUND
  fi

  # Cheap history sniff (only the last 50 refs touching sensitive globs)
  SENSITIVE=$(git log --oneline -50 --all -- '*.env' '*.pem' '*.key' '*secret*' '*credential*' 2>/dev/null | head -10 || true)
  if [[ -n "$SENSITIVE" ]]; then
    warn "Sensitive-named files in recent Git history:"
    rep "- ⚠️ **Sensitive filenames in Git history:**"
    rep "\`\`\`"
    printf '%s\n' "$SENSITIVE" >> "$REPORT_FILE"
    rep "\`\`\`"
    rep "  → \`git log --oneline --all -- '*.env' '*.key' '*.pem'\` for details"
    bump MANUAL_ACTIONS
  else
    rep "- ✅ No sensitive-named files in recent history"
  fi

  # Git credential helper — worm might tamper with this
  CRED_HELPER=$(git config --global --get credential.helper 2>/dev/null || echo "")
  if [[ -n "$CRED_HELPER" ]]; then
    rep "- ℹ️ Global \`credential.helper\` = \`${CRED_HELPER}\`"
    case "$CRED_HELPER" in
      osxkeychain|manager*|libsecret|store|cache|wincred|/usr/*|/Applications/*) : ;;
      *) warn "Unusual credential.helper — verify origin: ${CRED_HELPER}"
         bump MANUAL_ACTIONS ;;
    esac
  fi

  rep ""
fi

# ============================================================
section "8 · SSH key security"
# ============================================================

rep "## 8. SSH key security"
rep ""

SSH_DIR="${HOME}/.ssh"
if [[ -d "$SSH_DIR" ]]; then
  SSH_PERMS=$(file_perms "$SSH_DIR")
  if [[ "$SSH_PERMS" == "700" ]]; then
    ok "~/.ssh permissions: ${SSH_PERMS}"
    rep "- ✅ \`~/.ssh\` permissions: \`700\`"
  else
    warn "~/.ssh permissions ${SSH_PERMS} — should be 700"
    if do_action "chmod 700 ~/.ssh" chmod 700 "$SSH_DIR"; then
      rep "- 🔧 \`~/.ssh\` permissions \`${SSH_PERMS}\` → \`700\`"
      bump ISSUES_FIXED
    fi
    bump ISSUES_FOUND
  fi

  # All private keys (ANYTHING in ~/.ssh that isn't .pub / config / known_hosts)
  KEY_ISSUES=0
  KEY_IDX=0
  for keyfile in "${SSH_DIR}"/*; do
    [[ -f "$keyfile" ]] || continue
    base=$(basename "$keyfile")
    case "$base" in
      *.pub|config|known_hosts|known_hosts.old|authorized_keys|environment) continue ;;
    esac
    KEY_PERMS=$(file_perms "$keyfile")
    # Pseudonymize the key label by default — file names often encode
    # organizational scope (e.g. "client-prod-deploy"). GDPR Art. 5(1)(c)
    # data minimization + ISO A.8.12 DLP. --include-identity opts in to
    # the raw filename for the operator who needs it.
    KEY_IDX=$((KEY_IDX + 1))
    if [[ "${INCLUDE_IDENTITY:-0}" == "1" ]]; then
      LABEL="\`${base}\`"
    else
      LABEL="private key #${KEY_IDX} (name suppressed; use --include-identity)"
    fi
    if [[ "$KEY_PERMS" == "600" || "$KEY_PERMS" == "400" ]]; then
      ok "key ${base}: ${KEY_PERMS}"
      rep "- ✅ ${LABEL}: \`${KEY_PERMS}\`"
    else
      warn "key ${base}: ${KEY_PERMS} — fixing"
      if do_action "chmod 600 ${base}" chmod 600 "$keyfile"; then
        rep "- 🔧 ${LABEL}: \`${KEY_PERMS}\` → \`600\`"
        bump ISSUES_FIXED
      fi
      KEY_ISSUES=$((KEY_ISSUES + 1))
      bump ISSUES_FOUND
    fi
  done
  [[ "$KEY_ISSUES" -eq 0 ]] && rep "- ✅ All SSH private keys have secure permissions"

  # known_hosts entries with localhost / 0.0.0.0 — sometimes from worm
  if [[ -f "${SSH_DIR}/known_hosts" ]] \
     && grep -qE '^(0\.0\.0\.0|127\.0\.0\.1|localhost)' "${SSH_DIR}/known_hosts" 2>/dev/null; then
    warn "known_hosts contains localhost entries — review"
    rep "- ⚠️ \`known_hosts\` has localhost / 0.0.0.0 entries (review)"
    bump MANUAL_ACTIONS
  fi
else
  rep "- ℹ️ No \`~/.ssh\` directory"
fi
rep ""

# ============================================================
section "9 · npm registry & .npmrc"
# ============================================================

rep "## 9. npm registry & .npmrc"
rep ""

if command -v npm >/dev/null 2>&1; then
  REGISTRY=$(npm config get registry 2>/dev/null || echo "unknown")
  ok "Active registry: ${REGISTRY}"
  rep "- **Registry:** \`${REGISTRY}\`"
  if [[ "$REGISTRY" != "https://registry.npmjs.org/" ]]; then
    warn "Non-default registry — verify this is intentional"
    rep "  - ⚠️ Non-default registry. Make sure this is an intended private/mirror registry, not a hijack."
    bump MANUAL_ACTIONS
  fi
fi

NPMRC="${HOME}/.npmrc"
if [[ -f "$NPMRC" ]]; then
  NPMRC_PERMS=$(file_perms "$NPMRC")
  if [[ "$NPMRC_PERMS" == "600" || "$NPMRC_PERMS" == "400" ]]; then
    rep "- ✅ \`~/.npmrc\` permissions: \`${NPMRC_PERMS}\`"
  else
    warn "~/.npmrc permissions ${NPMRC_PERMS} — fixing"
    if do_action "chmod 600 ~/.npmrc" chmod 600 "$NPMRC"; then
      rep "- 🔧 \`~/.npmrc\` permissions \`${NPMRC_PERMS}\` → \`600\`"
      bump ISSUES_FIXED
    fi
    bump ISSUES_FOUND
  fi

  TOKEN_COUNT=$(grep -c "_authToken" "$NPMRC" 2>/dev/null || echo 0)
  if [[ "$TOKEN_COUNT" -gt 0 ]]; then
    ok "${TOKEN_COUNT} auth token(s) in ~/.npmrc"
    rep "- ✅ ${TOKEN_COUNT} auth token(s) (contents not logged)"
    # Cross-check: tokens registered for hosts OTHER than the default registry
    # are a strong signal of a hijacked .npmrc (Nemesis Finding 7).
    DEFAULT_HOST="registry.npmjs.org"
    SCOPES=$(grep -oE '^//[^/]+/?:_authToken' "$NPMRC" | sed 's/:_authToken//' | sort -u)
    if [[ -n "$SCOPES" ]]; then
      rep "  - Token registry scopes:"
      while IFS= read -r s; do
        rep "    - \`${s}\`"
        if [[ "$s" != *"$DEFAULT_HOST"* ]]; then
          warn "  Token registered for non-default host: $s"
          rep "    - ⚠️ Token for non-default host — verify this is a legitimate private registry."
          bump MANUAL_ACTIONS
        fi
      done <<< "$SCOPES"
    fi
  fi
fi
rep ""

# ============================================================
section "10 · Summary"
# ============================================================

# Flush the last section's manual-action delta before rendering the summary,
# so § 9 (the section before this one) gets attributed correctly.
if [[ -n "$_MA_SECTION_NAME" ]]; then
  _delta=$((MANUAL_ACTIONS - _MA_BASELINE))
  [[ $_delta -gt 0 ]] && MA_SECTIONS+=("§ ${_MA_SECTION_NAME} — ${_delta} item(s)")
fi

rep "---"
rep ""
rep "## Summary"
rep ""
rep "| Category | Value |"
rep "|----------|-------|"
rep "| **Mode** | ${SCAN_MODE} |"
rep "| **Blocking issues** | ${ISSUES_FOUND} (npm critical + high; counted as findings) |"
if [[ "$NONBLOCKING_ISSUES" -gt 0 ]]; then
  rep "| **Non-blocking** | ${NONBLOCKING_ISSUES} (npm moderate + low; review at next major update) |"
fi
rep "| **Auto-fixed** | ${ISSUES_FIXED} |"
rep "| **Worm IOC hits** | ${WORM_HITS} |"
rep "| **Quarantined** | ${QUARANTINED} |"
rep "| **Manual actions required** | ${MANUAL_ACTIONS} |"
rep ""

if [[ "$WORM_HITS" -gt 0 ]]; then
  rep "### 🚨 WORM / IOC HITS"
  rep ""
  rep "${WORM_HITS} supply-chain / worm indicator(s) detected. Treat this machine as **potentially compromised** until proven otherwise:"
  rep ""
  rep "1. Disconnect from sensitive networks if practical."
  rep "2. Rotate every credential reachable from this machine: npm tokens, GitHub PATs, AWS keys, SSH keys, all \`.env\` secrets."
  rep "3. \`rm -rf node_modules package-lock.json && npm ci\` after pinning safe versions."
  rep "4. Re-run with \`--quarantine\` to isolate flagged files (they go to \`~/.sec-scan-quarantine/\`)."
  rep "5. Inspect quarantined files manually before deletion."
  rep ""
fi

if [[ "$MANUAL_ACTIONS" -gt 0 ]]; then
  rep "### Manual actions required: ${MANUAL_ACTIONS}"
  rep ""
  if [[ "${#MA_SECTIONS[@]}" -gt 0 ]]; then
    rep "Contributing sections:"
    rep ""
    for _entry in "${MA_SECTIONS[@]}"; do
      rep "- ${_entry}"
    done
    rep ""
  fi
  rep "Open the report sections above for the specific items flagged."
  rep ""
fi

if [[ "$WORM_HITS" -eq 0 && "$MANUAL_ACTIONS" -eq 0 ]]; then
  rep "### ✅ Clean"
  rep ""
  rep "No worm IOCs detected, no manual actions required. Re-run regularly — npm supply-chain incidents are weekly."
  rep ""
fi

rep "---"
rep "_Generated by sec-scan.sh v${VERSION}._"
rep "_Report: \`$(rep_path "${REPORT_FILE}")\`_"
if [[ "$QUARANTINED" -gt 0 ]]; then
  rep "_Quarantine: \`$(rep_path "${QUARANTINE_DIR}")\`_"
fi

# ── Terminal summary ─────────────────────────────────────────
printf '\n%s╔════════════════════════════════════════╗%s\n' "$BOLD" "$RESET"
printf '%s║   Scan complete                        ║%s\n' "$BOLD" "$RESET"
printf '%s╠════════════════════════════════════════╣%s\n' "$BOLD" "$RESET"
printf '%s║%s Mode:     %-30s%s║%s\n' "$BOLD" "$RESET" "$SCAN_MODE" "$BOLD" "$RESET"
if [[ "$NONBLOCKING_ISSUES" -gt 0 ]]; then
  printf '%s║%s Found:    %-30s%s║%s\n' "$BOLD" "$RESET" "${ISSUES_FOUND} blocking, ${NONBLOCKING_ISSUES} non-block." "$BOLD" "$RESET"
else
  printf '%s║%s Found:    %-30s%s║%s\n' "$BOLD" "$RESET" "${ISSUES_FOUND} issue(s)" "$BOLD" "$RESET"
fi
printf '%s║%s Fixed:    %s%-30s%s%s║%s\n' "$BOLD" "$RESET" "$GREEN" "${ISSUES_FIXED} auto" "$RESET" "$BOLD" "$RESET"
printf '%s║%s Worm IOC: %s%-30s%s%s║%s\n' "$BOLD" "$RESET" "$RED" "${WORM_HITS} hit(s)" "$RESET" "$BOLD" "$RESET"
printf '%s║%s Manual:   %-30s%s║%s\n' "$BOLD" "$RESET" "${MANUAL_ACTIONS} action(s)" "$BOLD" "$RESET"
printf '%s╚════════════════════════════════════════╝%s\n' "$BOLD" "$RESET"
# If specific sections drove the manual-action count, surface them inline
# so the operator doesn't have to scroll the full report.
if [[ "${#MA_SECTIONS[@]}" -gt 0 ]]; then
  for _entry in "${MA_SECTIONS[@]}"; do
    printf '  %s↳%s %s\n' "$ORANGE" "$RESET" "$_entry"
  done
fi

if [[ "$WORM_HITS" -gt 0 ]]; then
  err "Worm IOC hits — rotate ALL credentials reachable from this machine."
  err "Re-run with --quarantine to isolate flagged artifacts."
fi
if [[ "$MANUAL_ACTIONS" -gt 0 ]]; then
  warn "Manual actions required — read the report:"
  printf '  %scat %s%s\n' "$BOLD" "$REPORT_FILE" "$RESET"
fi
if [[ "$WORM_HITS" -eq 0 && "$MANUAL_ACTIONS" -eq 0 ]]; then
  ok "All clean."
fi

printf '\nFull report: %s\n' "$REPORT_FILE"
[[ "$QUARANTINED" -gt 0 ]] && printf 'Quarantine:  %s\n' "$QUARANTINE_DIR"

# ── JSON sidecar for SIEM ingest ─────────────────────────────
# ISO 27001 A.6.8 + A.8.8 + A.16.1; NIS2 Art. 23 incident reporting.
# Mode 600 — confidentiality (Art. 32(2)).
JSON_FILE="${REPORT_DIR}/scan-report_${TIMESTAMP}.json"
SCAN_ID=$(uuidgen 2>/dev/null || printf '%s-%s' "$(date +%s)" "$RANDOM")
{
  printf '{\n'
  printf '  "scanId": "%s",\n' "$SCAN_ID"
  printf '  "scanner": {"name": "nyx-sec-scanner", "version": "%s"},\n' "$VERSION"
  printf '  "machineId": "%s",\n' "$MACHINE_ID"
  printf '  "timestamp": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '  "mode": "%s",\n' "$SCAN_MODE"
  printf '  "retentionDays": %d,\n' "$RETENTION_DAYS"
  printf '  "issuesFound": %d,\n' "$ISSUES_FOUND"
  printf '  "nonBlockingIssues": %d,\n' "$NONBLOCKING_ISSUES"
  printf '  "issuesFixed": %d,\n' "$ISSUES_FIXED"
  printf '  "wormHits": %d,\n' "$WORM_HITS"
  printf '  "quarantined": %d,\n' "$QUARANTINED"
  printf '  "manualActions": %d,\n' "$MANUAL_ACTIONS"
  printf '  "reportFile": "%s",\n' "$(rep_path "$REPORT_FILE")"
  printf '  "exitCode": %d,\n' "$(
    if [[ "$WORM_HITS" -gt 0 ]]; then echo 2
    elif [[ "$MANUAL_ACTIONS" -gt 0 ]]; then echo 1
    else echo 0
    fi
  )"
  printf '  "lawfulBasis": "GDPR Art. 6(1)(f) — legitimate interest",\n'
  printf '  "frameworks": ["ISO 27001:2022", "GDPR", "BSI IT-Grundschutz", "NIS2"]\n'
  printf '}\n'
} > "$JSON_FILE"
chmod 600 "$JSON_FILE"

# ── Tamper-evidence: SHA-256 of report + sidecar .sha256 ─────
# GDPR Art. 32(1)(b) integrity of processing; ISO A.8.15 / A.12.4 log integrity;
# NIS2 Art. 21(2)(g) supply-chain security (evidence non-repudiation).
{
  printf '\n---\n_Integrity:_ SHA-256 \\`%s\\`\n' \
    "$(shasum -a 256 "$REPORT_FILE" | awk '{print $1}')"
} >> "$REPORT_FILE"
shasum -a 256 "$REPORT_FILE" > "${REPORT_FILE}.sha256"
chmod 600 "${REPORT_FILE}.sha256"
ok "Integrity fingerprint: $(awk '{print substr($1,1,16)}' "${REPORT_FILE}.sha256")…"
printf 'JSON sidecar: %s\n' "$JSON_FILE"
printf 'Integrity:    %s\n' "${REPORT_FILE}.sha256"

# ── Optional email notification (M4) ─────────────────────────
# ISO A.16.1 / A.6.8 incident notification; NIS2 Art. 23 reporting obligation.
# Fail-silent when no MTA is configured — the operator may run this scan on
# a machine that legitimately cannot send mail. Never blocks the scan exit.
if [[ -n "$NOTIFY_EMAIL" ]]; then
  if command -v mailx >/dev/null 2>&1; then MAILER="mailx"
  elif command -v mail  >/dev/null 2>&1; then MAILER="mail"
  elif command -v msmtp >/dev/null 2>&1; then MAILER="msmtp"
  elif command -v sendmail >/dev/null 2>&1; then MAILER="sendmail"
  else MAILER=""
  fi

  if [[ -z "$MAILER" ]]; then
    warn "Notify requested but no MTA found (mailx/mail/msmtp/sendmail). Email skipped."
  else
    SUBJECT="[nyx-sec-scanner] ${SCAN_MODE} — ${MACHINE_ID} — worm:${WORM_HITS} manual:${MANUAL_ACTIONS}"
    BODY=$(
      printf 'nyx-sec-scanner summary\n'
      printf '=======================\n\n'
      printf 'Scan ID:      %s\n' "$SCAN_ID"
      printf 'Machine ID:   %s\n' "$MACHINE_ID"
      [[ "$INCLUDE_IDENTITY" == "1" ]] && printf 'Machine name: %s (user: %s)\n' "$MACHINE_NAME" "$(whoami)"
      printf 'Timestamp:    %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      printf 'Mode:         %s\n\n' "$SCAN_MODE"
      printf 'Findings:\n'
      printf '  worm IOC hits:    %d\n' "$WORM_HITS"
      printf '  issues found:     %d\n' "$ISSUES_FOUND"
      printf '  auto-fixed:       %d\n' "$ISSUES_FIXED"
      printf '  manual actions:   %d\n' "$MANUAL_ACTIONS"
      printf '  quarantined:      %d\n\n' "$QUARANTINED"
      printf 'Artifacts (on the scanned host):\n'
      printf '  report:   %s\n' "$(rep_path "$REPORT_FILE")"
      printf '  json:     %s\n' "$(rep_path "$JSON_FILE")"
      printf '  sha256:   %s\n\n' "$(rep_path "${REPORT_FILE}.sha256")"
      printf 'Lawful basis: GDPR Art. 6(1)(f) — legitimate interest.\n'
      printf 'This email contains operational security data. Treat as confidential.\n'
    )
    # Attachments: the operator-facing report, the SIEM-facing JSON, and the
    # tamper-evidence sidecar. All three are 600-mode and self-contained.
    # NOTE: this transmits the full report content across the configured MTA.
    # GDPR Art. 32(1)(a) — recipient mailbox + transport security become part
    # of the controller's responsibility once attachments leave this host.
    ATTACHMENTS=()
    for _f in "$REPORT_FILE" "$JSON_FILE" "${REPORT_FILE}.sha256"; do
      [[ -f "$_f" ]] && ATTACHMENTS+=( "$_f" )
    done

    # Portable wrapped base64 (RFC 2045 ≤76 chars/line). openssl is ubiquitous
    # on dev workstations; fall back to base64+fold if it isn't.
    b64_encode() {
      if command -v openssl >/dev/null 2>&1; then
        openssl base64 < "$1"
      else
        base64 < "$1" | tr -d '\n' | fold -w 76
      fi
    }

    case "$MAILER" in
      mailx|mail)
        # BSD/macOS mailx and s-nail accept "-a FILE" per attachment. GNU
        # mailutils' `mail` repurposes `-a` for headers — on that platform
        # the send fails and we fall through to the warn below; operator
        # should install msmtp or sendmail for reliable attachments.
        MAIL_ARGS=( -s "$SUBJECT" )
        for _f in "${ATTACHMENTS[@]}"; do MAIL_ARGS+=( -a "$_f" ); done
        MAIL_ARGS+=( "$NOTIFY_EMAIL" )
        printf '%s\n' "$BODY" | "$MAILER" "${MAIL_ARGS[@]}" 2>/dev/null && \
          ok "Notification email sent to ${NOTIFY_EMAIL} with ${#ATTACHMENTS[@]} attachment(s)" || \
          warn "Email send failed (MTA returned non-zero). If GNU mailutils is in use, '-a' differs — install msmtp/sendmail for reliable attachments." ;;
      msmtp|sendmail)
        BOUNDARY="nyx-sec-scanner-$(date +%s)-$$"
        {
          printf 'To: %s\n' "$NOTIFY_EMAIL"
          printf 'Subject: %s\n' "$SUBJECT"
          printf 'MIME-Version: 1.0\n'
          printf 'Content-Type: multipart/mixed; boundary="%s"\n\n' "$BOUNDARY"
          printf -- '--%s\n' "$BOUNDARY"
          printf 'Content-Type: text/plain; charset=UTF-8\n'
          printf 'Content-Transfer-Encoding: 8bit\n\n'
          printf '%s\n' "$BODY"
          for _f in "${ATTACHMENTS[@]}"; do
            _fname=$(basename "$_f")
            case "$_f" in
              *.json)   _ctype="application/json" ;;
              *.sha256) _ctype="text/plain" ;;
              *)        _ctype="text/markdown" ;;
            esac
            printf -- '\n--%s\n' "$BOUNDARY"
            printf 'Content-Type: %s; name="%s"\n' "$_ctype" "$_fname"
            printf 'Content-Transfer-Encoding: base64\n'
            printf 'Content-Disposition: attachment; filename="%s"\n\n' "$_fname"
            b64_encode "$_f"
          done
          printf -- '\n--%s--\n' "$BOUNDARY"
        } | "$MAILER" -t 2>/dev/null && \
          ok "Notification email sent via ${MAILER} to ${NOTIFY_EMAIL} with ${#ATTACHMENTS[@]} attachment(s)" || \
          warn "${MAILER} send failed" ;;
    esac
  fi
fi

# Exit code: 2 if worm hit, 1 if manual actions, 0 if clean
if [[ "$WORM_HITS" -gt 0 ]]; then exit 2
elif [[ "$MANUAL_ACTIONS" -gt 0 ]]; then exit 1
else exit 0
fi
