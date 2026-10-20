#!/usr/bin/env bash
# 13-gh-add-security-md.sh
# Summary: Add a SECURITY.md to the default branch of one or more
# repositories when the file is missing, using the GitHub CLI (`gh`).
#
# This closes the one gap that the audit (99-gh-audit-security.sh) reports
# on repositories that have private vulnerability reporting enabled but no
# security policy for reporters to read.
#
# Prerequisites:
#  - `gh` installed and authenticated: `gh auth login`
#  - Write access to the target repositories
#
# Usage:
#  OWNER="username" bash 13-gh-add-security-md.sh
#  REPOS="repo1,repo2" OWNER="username" bash 13-gh-add-security-md.sh
#  DRY_RUN=1 bash 13-gh-add-security-md.sh
#  SECURITY_FILE=./my-security.md bash 13-gh-add-security-md.sh
#  Default target: all public repos of OWNER.
#
# Environment:
#  - SECURITY_FILE     local Markdown file to use instead of the built-in
#                      template. The literal token {{REPO}} is replaced with
#                      owner/repo for each repository.
#  - SECURITY_COMMIT   commit message (default: "docs: add SECURITY.md")
#  - DRY_RUN=1         print what would be committed, write nothing
#
# Behaviour: existing SECURITY.md files are never overwritten (reported as
# "already"); repositories without any commits are skipped.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

SECURITY_FILE=${SECURITY_FILE:-}
SECURITY_COMMIT=${SECURITY_COMMIT:-"docs: add SECURITY.md"}

if [[ -n "$SECURITY_FILE" && ! -f "$SECURITY_FILE" ]]; then
  die "SECURITY_FILE not found: $SECURITY_FILE"
fi

# Built-in template. {{REPO}} is substituted per repository.
default_template() {
  cat <<'EOF'
# Security Policy

## Reporting a Vulnerability

Please **do not** report security vulnerabilities through public GitHub issues.

Use GitHub's private vulnerability reporting instead:

{{REPO_SECURITY_URL}}

When you report it, include:

- the affected component and version (or commit)
- steps to reproduce the issue
- the potential impact

You should receive an acknowledgement within a few days. Please allow me a
reasonable amount of time to fix the issue before any public disclosure.

## Automated Coverage

This repository uses GitHub's built-in protections:

- secret scanning and push protection for leaked credentials
- Dependabot alerts and security updates for vulnerable dependencies
- code scanning (CodeQL) for source code issues

They complement, but do not replace, vulnerability reports from people.
EOF
}

if [[ -n "$SECURITY_FILE" ]]; then
  template="$(cat "$SECURITY_FILE")"
else
  template="$(default_template)"
fi

payload="$(mk_payload_file)"
trap 'rm -f "$payload"' EXIT

init_targets
log "Adding SECURITY.md to ${#TARGETS[@]} repositories (existing files are kept)..."

for repo in "${TARGETS[@]}"; do
  repo_header "$repo"

  if is_archived "$repo"; then
    skipped "archived repository"
    continue
  fi

  # Never overwrite an existing security policy.
  if gh api "repos/$repo/contents/SECURITY.md" --jq .name >/dev/null 2>&1; then
    already "SECURITY.md exists"
    continue
  fi

  default_branch="$(get_repo "$repo" '.default_branch' '')"
  if [[ -z "$default_branch" ]]; then
    skipped "could not determine the default branch (empty repository?)"
    continue
  fi

  content="${template//\{\{REPO\}\}/$repo}"
  content="${content//\{\{REPO_SECURITY_URL\}\}/https://github.com/$repo/security/advisories/new}"

  b64="$(printf '%s' "$content" | base64 -w0 2>/dev/null || printf '%s' "$content" | base64 | tr -d '\n')"

  printf '{"message":"%s","content":"%s","branch":"%s"}' \
    "${SECURITY_COMMIT//\"/}" "$b64" "$default_branch" >"$payload"

  if [[ "$DRY_RUN" == "1" ]]; then
    log "  -> would commit SECURITY.md ($(printf '%s' "$content" | wc -l) lines) to $default_branch"
    step "SECURITY.md added to $default_branch" true
  else
    step "SECURITY.md committed to $default_branch" \
      gh api "repos/$repo/contents/SECURITY.md" --method PUT --input "$payload" \
      --jq '.commit.sha'
  fi
done

finish
