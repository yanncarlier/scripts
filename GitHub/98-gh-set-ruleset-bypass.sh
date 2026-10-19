#!/usr/bin/env bash
# 14-gh-set-ruleset-bypass.sh
# Summary: Replace the bypass actor list of the branch protection ruleset for
# one or more repositories, using the GitHub CLI (`gh`). Every existing bypass
# entry is removed and the single GitHub user passed as an argument is added as
# the only bypass actor.
#
# Prerequisites:
#  - `gh` installed and authenticated with admin access to target repos.
#
# Usage:
#   bash 14-gh-set-ruleset-bypass.sh <github-username>
#   OWNER="username" REPOS="repo1,repo2" bash 14-gh-set-ruleset-bypass.sh octocat
#   BYPASS_MODE=pull_request bash 14-gh-set-ruleset-bypass.sh octocat
#   DRY_RUN=1 bash 14-gh-set-ruleset-bypass.sh octocat
#
# Environment variables:
#  - RULESET_NAME  ruleset whose bypass list is edited
#                  (default: protect-default-branch)
#  - BYPASS_USER   username, used when no positional argument is given
#  - BYPASS_MODE   always | pull_request | exempt (default: always)
#  - API_VERSION   X-GitHub-Api-Version sent to the API
#                  (default: 2026-03-10, needed for User bypass actors;
#                  set to "" to let gh pick)
#  - OWNER, REPOS, DRY_RUN, VERBOSE, NO_COLOR (see lib/common.sh)
#
# WARNING: every existing bypass actor of the ruleset is removed and replaced
# by the single user given. Check the current bypass list before running.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

# === CONFIGURATION =======================================================

RULESET_NAME=${RULESET_NAME:-protect-default-branch}
BYPASS_MODE=${BYPASS_MODE:-always}
BYPASS_USER=${1:-${BYPASS_USER:-}}
API_VERSION=${API_VERSION:-2026-03-10}

# Individual users in a bypass list require a recent API version; skip the
# header when API_VERSION is empty.
ghapi() {
  if [[ -n "$API_VERSION" ]]; then
    gh api --header "X-GitHub-Api-Version: $API_VERSION" "$@"
  else
    gh api "$@"
  fi
}

# === VALIDATION ==========================================================

[[ -n "$BYPASS_USER" ]] ||
  die "usage: bash $(basename "${BASH_SOURCE[0]}") <github-username>  (or set BYPASS_USER)"

[[ "$RULESET_NAME" =~ ^[A-Za-z0-9._\ -]+$ ]] ||
  die "RULESET_NAME may only contain letters, digits, spaces, dot, dash and underscore"

[[ "$BYPASS_MODE" == "always" || "$BYPASS_MODE" == "pull_request" || "$BYPASS_MODE" == "exempt" ]] ||
  die "BYPASS_MODE must be always, pull_request or exempt (got: $BYPASS_MODE)"

[[ "$BYPASS_USER" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,38}[A-Za-z0-9])?$ ]] ||
  die "not a valid GitHub username: $BYPASS_USER"

# === RESOLVE THE USER ====================================================

require_gh

user_type="$(ghapi "users/$BYPASS_USER" --jq '.type' 2>/dev/null || true)"
case "$user_type" in
  User) ;;
  "") die "GitHub user '$BYPASS_USER' not found" ;;
  *) die "'$BYPASS_USER' is a $user_type account, not a user" ;;
esac

BYPASS_ACTOR_ID="$(ghapi "users/$BYPASS_USER" --jq '.id' 2>/dev/null || true)"
[[ "$BYPASS_ACTOR_ID" =~ ^[0-9]+$ ]] ||
  die "could not resolve '$BYPASS_USER' to a user id"

# === API HELPERS =========================================================

# Print "<removed-count> <same>" for a ruleset, where <same> is 1 when the
# bypass list already contains exactly the target user and nothing else.
bypass_state() {
  ghapi "repos/$1/rulesets/$2" --jq "
    ((.bypass_actors // []) | length) as \$n
    | ((\$n == 1)
       and (.bypass_actors[0].actor_type == \"User\")
       and (.bypass_actors[0].actor_id == $BYPASS_ACTOR_ID)
       and (.bypass_actors[0].bypass_mode == \"$BYPASS_MODE\")) as \$same
    | \"\(\$n) \(if \$same then 1 else 0 end)\"
  "
}

# Print the full update payload for a ruleset with the bypass list replaced.
build_payload() {
  ghapi "repos/$1/rulesets/$2" --jq "{
    name: .name,
    target: .target,
    enforcement: .enforcement,
    conditions: .conditions,
    rules: .rules,
    bypass_actors: [
      { actor_id: $BYPASS_ACTOR_ID, actor_type: \"User\", bypass_mode: \"$BYPASS_MODE\" }
    ]
  }"
}

payload="$(mk_payload_file)"
trap 'rm -f "$payload"' EXIT

# === APPLY ===============================================================

init_targets
log "Setting the bypass list of ruleset '$RULESET_NAME' to $BYPASS_USER (id $BYPASS_ACTOR_ID, mode $BYPASS_MODE)..."

for repo in "${TARGETS[@]}"; do
  repo_header "$repo"

  if is_archived "$repo"; then
    skipped "archived repository"
    continue
  fi

  # Only consider rulesets owned by this repository (not org-level ones).
  ruleset_id="$(
    gh api "repos/$repo/rulesets?includes_parents=false" \
      --jq "map(select(.name == \"$RULESET_NAME\")) | .[0].id // empty" 2>/dev/null || true
  )"

  if [[ -z "$ruleset_id" ]]; then
    skipped "ruleset '$RULESET_NAME' not found"
    continue
  fi

  state="$(bypass_state "$repo" "$ruleset_id" 2>/dev/null || true)"
  if [[ -z "$state" ]]; then
    printf '  %sFAILED:%s could not read ruleset %s\n' "$C_RED" "$C_OFF" "$ruleset_id"
    C_FAIL=$((C_FAIL + 1))
    continue
  fi

  read -r removed is_same <<<"$state"

  if [[ "$is_same" == "1" ]]; then
    already "bypass list already limited to $BYPASS_USER"
    continue
  fi

  if ! build_payload "$repo" "$ruleset_id" >"$payload"; then
    printf '  %sFAILED:%s could not build the payload for ruleset %s\n' "$C_RED" "$C_OFF" "$ruleset_id"
    C_FAIL=$((C_FAIL + 1))
    continue
  fi

  log "  bypass entries removed: $removed"
  if [[ "$DRY_RUN" == "1" ]]; then
    log "  payload:"
    sed 's/^/    /' "$payload"
  fi

  step "ruleset '$RULESET_NAME' bypass list replaced with $BYPASS_USER" \
    ghapi "repos/$repo/rulesets/$ruleset_id" \
    --method PUT --input "$payload"

  log "  -> https://github.com/$repo/settings/rules"
done

finish
