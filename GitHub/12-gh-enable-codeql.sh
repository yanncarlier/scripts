#!/usr/bin/env bash
# 12-gh-enable-codeql.sh
# Summary: Enable CodeQL default setup (code scanning) for one or more
# repositories using the GitHub CLI (`gh`).
#
# This is the counterpart of destructive/24-gh-disable-codeql.sh, which uses
# the same endpoint with state=not-configured.
#
# Prerequisites:
#  - `gh` installed and authenticated: `gh auth login`
#  - Admin access to the target repositories
#  - Code scanning default setup must be available for the repository
#    (free for public repositories)
#
# Usage:
#  OWNER="username" bash 12-gh-enable-codeql.sh
#  REPOS="repo1,repo2" OWNER="username" bash 12-gh-enable-codeql.sh
#  DRY_RUN=1 QUERY_SUITE=extended bash 12-gh-enable-codeql.sh
#  Default target: all public repos of OWNER.
#
# Environment:
#  - QUERY_SUITE  default | extended  (omit to keep the current/default suite)
#  - THREAT_MODEL remote | remote_and_local (omit to keep the current/default)
#
# Notes:
#  - The API answers 202 Accepted: GitHub starts a validation run and the
#    first analysis can take a few minutes before alerts appear.
#  - 409 means a validation run is already in progress - re-run later.
#  - Languages are auto-detected unless you set them on the repository.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

QUERY_SUITE=${QUERY_SUITE:-}
THREAT_MODEL=${THREAT_MODEL:-}

if [[ -n "$QUERY_SUITE" && "$QUERY_SUITE" != "default" && "$QUERY_SUITE" != "extended" ]]; then
  die "QUERY_SUITE must be 'default' or 'extended' (got: $QUERY_SUITE)"
fi
if [[ -n "$THREAT_MODEL" && "$THREAT_MODEL" != "remote" && "$THREAT_MODEL" != "remote_and_local" ]]; then
  die "THREAT_MODEL must be 'remote' or 'remote_and_local' (got: $THREAT_MODEL)"
fi

init_targets
log "Enabling CodeQL default setup for ${#TARGETS[@]} repositories..."

for repo in "${TARGETS[@]}"; do
  repo_header "$repo"

  if is_archived "$repo"; then
    skipped "archived repository"
    continue
  fi

  state="$(gh api "repos/$repo/code-scanning/default-setup" --jq '.state // "unknown"' 2>/dev/null || echo "?")"
  if [[ "$state" == "configured" ]]; then
    already "CodeQL default setup"
    continue
  fi
  log "  current state: $state"

  args=(--method PATCH -f state=configured)
  if [[ -n "$QUERY_SUITE" ]]; then
    args+=(-f "query_suite=$QUERY_SUITE")
  fi
  if [[ -n "$THREAT_MODEL" ]]; then
    args+=(-f "threat_model=$THREAT_MODEL")
  fi

  step "CodeQL default setup enabled (analysis queued)" \
    gh api "repos/$repo/code-scanning/default-setup" "${args[@]}"
done

finish
