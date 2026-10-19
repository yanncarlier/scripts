# GitHub Security Scripts

Use at your own risk.
Bash scripts that harden GitHub repositories with the GitHub CLI (`gh`): secret
scanning, push protection, branch protection rulesets, Dependabot, private
vulnerability reporting and dependency snapshots - plus an audit script that
verifies the result.

## Prerequisites

- GitHub CLI installed: https://cli.github.com
- Authenticated: `gh auth login`
- Admin access to the target repositories
- `python3` (only for `08-gh-auto-dependency-submission.sh`)

## Quick start

```bash
# Dry run first: prints what would change, writes nothing
DRY_RUN=1 OWNER="my-org" bash 00-run-all.sh

# Apply everything (01 -> 11) and then audit the result
OWNER="my-org" bash 00-run-all.sh

# Only some steps
OWNER="my-org" bash 00-run-all.sh 02 04
OWNER="my-org" ONLY="03,05" bash 00-run-all.sh
```

Every script is idempotent: it reads the current state first and reports
`already` instead of re-applying, so re-running is always safe.

## Environment variables (shared by all scripts)

| Variable | Meaning | Default |
|---|---|---|
| `OWNER` | GitHub user or organization | login of `gh api user` |
| `REPOS` | Comma separated targets, `repo1,other/repo2` | all public, non-fork repos of `OWNER` |
| `DRY_RUN=1` | Print mutating calls instead of performing them | `0` |
| `VERBOSE=1` | Print every `gh` command | `0` |
| `NO_COLOR=1` | Disable ANSI colors | colors when TTY |

Exit codes: `0` when everything succeeded, `1` when at least one repository
failed (or, for the audit, when a check found a gap).

## Script reference

| Script | Purpose |
|---|---|
| `00-run-all.sh` | Run 01-11 in order, then the audit; prints a pass/fail summary and does **not** stop at the first failure |
| `01-gh-setup-dev-branches.sh` | Create the development branch (`DEV_BRANCH`, default `dev`) when missing |
| `02-gh-enable-secret-scanning.sh` | Enable secret scanning |
| `03-gh-setup-rulesets.sh` | Create **or update** the branch protection ruleset (see below) |
| `04-gh-enable-push-protection.sh` | Enable push protection (requires `02` first) |
| `05-gh-copilot-code-review.sh` | Create/update the Copilot code review ruleset (`copilot_code_review`) |
| `06-gh-enable-private-vuln-reporting.sh` | Let people report vulnerabilities privately |
| `07-gh-enable-dependency-graph.sh` | Enable dependency graph + dependency alerts |
| `08-gh-auto-dependency-submission.sh` | Build and POST a dependency snapshot from the repo's manifests |
| `09-gh-enable-dependabot-alerts.sh` | Enable Dependabot alerts |
| `10-gh-enable-dependabot-security-updates.sh` | Enable Dependabot auto-fix PRs (a different toggle from alerts) |
| `11-gh-enable-dependabot-malware-alerts.sh` | Malware alert coverage - same toggle as `07`/`09`, kept as a labelled step |
| `12-gh-enable-codeql.sh` | Enable CodeQL default setup (counterpart of `destructive/24`) |
| `13-gh-add-security-md.sh` | Commit a `SECURITY.md` when the repository has none (never overwrites) |
| `14-gh-set-ruleset-bypass.sh` | Replace a ruleset's whole bypass list with one user (passed as an argument) |
| `99-gh-audit-security.sh` | **Read-only** compliance report, exits non-zero on gaps |
| `destructive/20-gh-delete-rulesets.sh` | Deletes all rulesets (destructive) |
| `destructive/24-gh-disable-codeql.sh` | Disables CodeQL default setup (destructive) |
| `git_fetch_pull_all_subfolders.sh` | Helper for git fetch/pull across nested folders |

`lib/common.sh` holds the shared logic (repository resolution, archived skip,
retry-on-rate-limit, dry-run, counters, exit codes). Every script sources it.

## Recommended order for a new repository

1. `01` - create the development branch
2. `02` - secret scanning
3. `04` - push protection (needs `02`)
4. `06` - private vulnerability reporting
5. `07` - dependency graph + dependency alerts
6. `08` - dependency snapshot (needs `07`; requires a supported manifest)
7. `09` / `11` - Dependabot / malware alerts (same toggle as `07`, so usually `already`)
8. `10` - Dependabot security updates
9. `03` - branch protection ruleset
10. `05` - Copilot code review ruleset (needs `03`'s world in place)
11. `12` - CodeQL default setup
12. `13` - `SECURITY.md` for repositories that do not have one
13. `99` - audit everything

`00-run-all.sh` runs exactly this order (numerically, then the audit).

## The ruleset (`03`)

Unlike the previous version this script **updates the existing ruleset in
place** instead of deleting and recreating it, so protection never drops
during a re-run. Defaults are intentionally strict:

```bash
RULESET_NAME=protect-default-branch   # name it manages
PROTECT_BRANCHES="~DEFAULT_BRANCH,refs/heads/dev"
REQUIRED_APPROVALS=1                  # was 0 before
REQUIRE_LAST_PUSH_APPROVAL=1          # no self-approval of your own push
REQUIRE_THREAD_RESOLUTION=1           # conversations must be resolved
BLOCK_DIRECT_PUSH=1                   # non-bypass roles must use a PR
REQUIRE_LINEAR_HISTORY=0              # 1 forbids merge commits
BYPASS_MODE=always                    # always | pull_request | exempt
```

Bypass is granted to `RepositoryRole` id 5 (repository admin), so on a
personal repository *you* keep full control; collaborators are forced through
a reviewed PR. Use `BYPASS_MODE=pull_request` if admins should never be able
to push straight to a protected branch.

Preview the payload without applying it:

```bash
DRY_RUN=1 bash 03-gh-setup-rulesets.sh
```

## Replacing the ruleset bypass list (`14`)

`14-gh-set-ruleset-bypass.sh` removes **every** existing bypass actor of the
ruleset and adds a single user as the only bypass actor. The user is passed as
an argument (or via `BYPASS_USER`):

```bash
bash 14-gh-set-ruleset-bypass.sh octocat
OWNER="my-org" REPOS="repo1,repo2" bash 14-gh-set-ruleset-bypass.sh octocat
BYPASS_MODE=pull_request bash 14-gh-set-ruleset-bypass.sh octocat
RULESET_NAME=my-ruleset bash 14-gh-set-ruleset-bypass.sh octocat
DRY_RUN=1 bash 14-gh-set-ruleset-bypass.sh octocat
```

The username is resolved to a user id and added with `actor_type: "User"`;
individual users in a bypass list require a recent API version, so the script
sends `X-GitHub-Api-Version: 2026-03-10` by default (override with
`API_VERSION`). The ruleset's rules and conditions are preserved: the script
reads the ruleset, replaces only `bypass_actors` and writes it back with `PUT`.

This script is intentionally **not** part of `00-run-all.sh`: it needs an
argument and it deliberately wipes the existing bypass list.

## The audit (`99`)

One row per repository:

| Column | Meaning |
|---|---|
| `SECRET` | secret scanning |
| `PUSH` | secret scanning push protection |
| `PRIVVR` | private vulnerability reporting |
| `ALERTS` | Dependabot alerts / malware alert coverage |
| `UPDATES` | Dependabot security updates |
| `RULESET` | the `03` ruleset exists on the repository |
| `SECMD` | `SECURITY.md` exists in the repository root |
| `CODEQL` | CodeQL default setup is `configured` |

```bash
OWNER="my-org" bash 99-gh-audit-security.sh          # table + exit 1 on gaps
REPORT=audit.tsv bash 99-gh-audit-security.sh         # also write a TSV
AUDIT_STRICT=0 bash 99-gh-audit-security.sh           # report only, exit 0
```

`00-run-all.sh` runs the audit last (disable with `AUDIT=0`). A failing audit
is reported as `GAPS FOUND`, not as a broken script.

## Notes and gotchas

- `07`, `09` and `11` all call `PUT /repos/{o}/{r}/vulnerability-alerts`; that
  single toggle covers the dependency graph, Dependabot alerts and malware
  alert coverage. Only the first one actually writes, the others report `already`.
- `04` refuses to run (and says why) when secret scanning is not enabled.
- `13` creates `SECURITY.md` when it is missing (one commit per repository)
  and never overwrites an existing policy.
- `08` snapshots only the repository root manifests and only pinned (`==`)
  dependencies. For continuous coverage, prefer the official dependency
  submission action in GitHub Actions.
- `05` requires Copilot code review to be available for the owner; if it is
  not, the API error is printed per repository instead of being swallowed.
- Forks are excluded from the default target list; archived repositories are
  always skipped.

## Testing without touching your repositories

```bash
# 1. syntax
bash -n *.sh lib/common.sh

# 2. shellcheck (recommended)
shellcheck -S warning 0*.sh 1*.sh 9*.sh lib/common.sh

# 3. dry run against the real API - reads state, writes nothing
DRY_RUN=1 OWNER=you bash 00-run-all.sh
```

## Troubleshooting

- `gh is not authenticated` -> `gh auth login`
- `No repositories found` -> check `OWNER`, or set `REPOS` explicitly
- `403/422` on a security toggle -> the account needs admin rights, and the
  feature must be available for the repository (public repositories include
  secret scanning, push protection, dependency graph and Dependabot alerts)
- Rate limits are retried automatically (up to 3 attempts with backoff)
