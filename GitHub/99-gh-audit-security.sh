#!/usr/bin/env bash
# 99-gh-audit-security.sh
# Summary: Read-only compliance report for the settings applied by scripts
# 01-11. Prints one row per repository and exits non-zero when a check fails,
# so it can run in CI or on a schedule.
#
# Columns:
#   SECRET   secret scanning
#   PUSH     secret scanning push protection
#   PRIVVR   private vulnerability reporting
#   ALERTS   Dependabot alerts / malware alert coverage
#   UPDATES  Dependabot security updates (auto-fix PRs)
#   RULESET  branch protection ruleset created by 03
#   SECMD    SECURITY.md present in the repository root
#   CODEQL   CodeQL default setup (configured / not configured / unknown)
#
# Prerequisites:
#  - `gh` installed and authenticated: `gh auth login`
#  - Admin access to the target repositories
#
# Usage:
#  OWNER="username" bash 99-gh-audit-security.sh
#  REPOS="repo1,repo2" OWNER="username" bash 99-gh-audit-security.sh
#  REPORT=audit.tsv bash 99-gh-audit-security.sh     # also write a TSV file
#  AUDIT_STRICT=0 bash 99-gh-audit-security.sh        # always exit 0
#
# Environment:
#  - OWNER, REPOS    see lib/common.sh
#  - RULESET_NAME    ruleset to look for (default: protect-default-branch)
#  - REPORT          optional path for a tab separated report
#  - AUDIT_STRICT    1 = exit 1 when a check fails (default)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

RULESET_NAME=${RULESET_NAME:-protect-default-branch}
REPORT=${REPORT:-}
AUDIT_STRICT=${AUDIT_STRICT:-1}

init_targets

# Y / N / ? normalisation
cell() { if [[ "$1" == "$2" ]]; then printf 'Y'; else printf 'N'; fi; }

header() {
  printf '%-42s %-6s %-6s %-6s %-7s %-7s %-8s %-6s %-7s %s\n' \
    "REPOSITORY" "SECRET" "PUSH" "PRIVVR" "ALERTS" "UPDATES" "RULESET" "SECMD" "CODEQL" "STATUS"
  printf '%s\n' "---------------------------------------------------------------------------------------------------------------"
}

if [[ -n "$REPORT" ]]; then
  printf 'repository\tsecret\tpush\tprivvr\talerts\tupdates\truleset\tsecmd\tcodeql\tstatus\n' >"$REPORT"
fi

header

gaps=0
gap_list=()

for repo in "${TARGETS[@]}"; do
  # One call for most of the fields.
  line="$(gh api "repos/$repo" --jq '[
      .archived,
      (.security_and_analysis.secret_scanning.status // "?"),
      (.security_and_analysis.secret_scanning_push_protection.status // "?"),
      (.security_and_analysis.dependabot_security_updates.status // "?")
    ] | @tsv' 2>/dev/null || true)"

  if [[ -z "$line" ]]; then
    printf '%-42s %-6s\n' "$repo" "ERROR"
    printf '%-42s %s\n' "" "cannot read repository (missing admin access or wrong name)"
    gaps=$((gaps + 1))
    gap_list+=("$repo: unreadable")
    continue
  fi

  IFS=$'\t' read -r archived secret push dsu <<<"$line"

  if [[ "$archived" == "true" ]]; then
    printf '%-42s %-6s %-6s %-6s %-7s %-7s %-8s %-6s %-7s %s\n' \
      "$repo" "-" "-" "-" "-" "-" "-" "-" "-" "archived"
    if [[ -n "$REPORT" ]]; then
      printf '%s\tarchived\t-\t-\t-\t-\t-\t-\t-\tarchived\n' "$repo" >>"$REPORT"
    fi
    continue
  fi

  # Y / N / ? normalisation
  c_secret="$(cell "$secret" enabled)"
  c_push="$(cell "$push" enabled)"

  # Private vulnerability reporting
  pvr="$(gh api "repos/$repo/private-vulnerability-reporting" --jq '.enabled' 2>/dev/null || echo "?")"
  if [[ "$pvr" == "true" ]]; then c_pvr="Y"; elif [[ "$pvr" == "false" ]]; then c_pvr="N"; else c_pvr="?"; fi

  # Dependabot alerts (same toggle as malware alert coverage).
  # NOTE: the repository payload's has_vulnerability_alerts field comes back
  # null for many tokens, so use the dedicated endpoint - the same one the
  # enable scripts (07/09/11) use, keeping both sides consistent.
  if gh api "repos/$repo/vulnerability-alerts" >/dev/null 2>&1; then
    c_alerts="Y"
  else
    c_alerts="N"
  fi

  # Dependabot security updates: fall back to the dedicated endpoint when the
  # security_and_analysis block does not report a status.
  if [[ "$dsu" == "enabled" ]]; then
    c_updates="Y"
  elif [[ "$dsu" == "disabled" ]]; then
    c_updates="N"
  else
    if gh api "repos/$repo/automated-security-fixes" --jq '.enabled' 2>/dev/null | grep -qx true; then
      c_updates="Y"
    else
      c_updates="N"
    fi
  fi

  # Ruleset owned by this repository (org level rulesets are ignored).
  rulesets="$(gh api "repos/$repo/rulesets?includes_parents=false" \
    --jq "[.[] | select(.name == \"$RULESET_NAME\")] | length" 2>/dev/null || echo "?")"
  if [[ "$rulesets" == "?" ]]; then
    c_ruleset="?"
  elif [[ "$rulesets" =~ ^[0-9]+$ ]] && ((rulesets >= 1)); then
    c_ruleset="Y"
  else
    c_ruleset="N"
  fi

  # SECURITY.md in the repository root
  if gh api "repos/$repo/contents/SECURITY.md" --jq .name >/dev/null 2>&1; then
    c_secmd="Y"
  else
    c_secmd="N"
  fi

  # Code scanning (CodeQL) default setup - read the real state instead of
  # guessing from the alerts endpoint (same endpoint destructive/24 uses).
  cs_state="$(gh api "repos/$repo/code-scanning/default-setup" \
    --jq '.state // "unknown"' 2>/dev/null || echo "?")"
  if [[ "$cs_state" == "configured" ]]; then
    c_codeql="Y"
  elif [[ "$cs_state" == "not-configured" ]]; then
    c_codeql="N"
  else
    c_codeql="?"
  fi

  # Status
  problems=()
  for pair in \
    "$c_secret:secret scanning" \
    "$c_push:push protection" \
    "$c_pvr:private vulnerability reporting" \
    "$c_alerts:Dependabot alerts" \
    "$c_updates:Dependabot security updates" \
    "$c_ruleset:ruleset '$RULESET_NAME'" \
    "$c_secmd:SECURITY.md" \
    "$c_codeql:CodeQL default setup"; do
    if [[ "${pair%%:*}" == "N" ]]; then
      problems+=("${pair#*:}")
    fi
  done

  unknown=0
  for v in "$c_secret" "$c_push" "$c_pvr" "$c_alerts" "$c_updates" "$c_ruleset" "$c_secmd" "$c_codeql"; do
    if [[ "$v" == "?" ]]; then
      unknown=$((unknown + 1))
    fi
  done

  if ((${#problems[@]} > 0)); then
    gap_str=""
    for p in "${problems[@]}"; do
      gap_str+="${gap_str:+, }$p"
    done
    status="GAP: $gap_str"
    gaps=$((gaps + 1))
    gap_list+=("$repo: $gap_str")
  elif ((unknown > 0)); then
    status="OK ($unknown unknown)"
  else
    status="OK"
  fi

  printf '%-42s %-6s %-6s %-6s %-7s %-7s %-8s %-6s %-7s %s\n' \
    "$repo" "$c_secret" "$c_push" "$c_pvr" "$c_alerts" "$c_updates" "$c_ruleset" "$c_secmd" "$c_codeql" "$status"

  if [[ -n "$REPORT" ]]; then
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$repo" "$c_secret" "$c_push" "$c_pvr" "$c_alerts" "$c_updates" "$c_ruleset" "$c_secmd" "$c_codeql" "$status" >>"$REPORT"
  fi
done

echo ""
echo "=================================================="
if [[ -n "$REPORT" ]]; then
  echo "Report written to: $REPORT"
fi
echo "Repositories with gaps: $gaps of ${#TARGETS[@]}"
if ((${#gap_list[@]} > 0)); then
  echo "--------------------------------------------------"
  for g in "${gap_list[@]}"; do
    printf '  %s\n' "$g"
  done
fi
echo "=================================================="

if ((gaps > 0)) && [[ "$AUDIT_STRICT" == "1" ]]; then
  exit 1
fi
exit 0
