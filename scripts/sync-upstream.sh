#!/usr/bin/env bash
# Sync between this monorepo subtree and etzhayyim/kotoba (public upstream).
#
# Usage:
#   ./scripts/sync-upstream.sh push [commit-message]
#       Copy source → public repo (excludes CLAUDE.md, deps.toml; patches Cargo.toml),
#       commit and push to etzhayyim/kotoba main.
#
#   ./scripts/sync-upstream.sh pull
#       Fetch latest etzhayyim/kotoba main → apply to this directory
#       (preserves CLAUDE.md, deps.toml; patches Cargo.toml back).
#
# Remote required (one-time setup, already done):
#   git remote add kotoba-upstream git@github.com:etzhayyim/kotoba.git
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KOTOBA_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${KOTOBA_DIR}/../.." && pwd)"
UPSTREAM_REMOTE="kotoba-upstream"
UPSTREAM_BRANCH="main"
WORKTREE_DIR="${TMPDIR:-/tmp}/kotoba-upstream-wt"

# Files/dirs present only in monorepo — never pushed to public upstream
MONOREPO_ONLY=(
    "CLAUDE.md"
    "deps.toml"
    ".cargo/"
)

# Cargo.toml fields that differ between monorepo and public upstream
MONOREPO_LICENSE="UNLICENSED"
MONOREPO_AUTHORS='"Gftd Japan <dev@gftd.group>"'
UPSTREAM_LICENSE="Apache-2.0"
UPSTREAM_AUTHORS='"etzhayyim <dev@etzhayyim.com>"'
UPSTREAM_REPO='repository = "https://github.com/etzhayyim/kotoba"'

die() { echo "ERROR: $*" >&2; exit 1; }

# ── helpers ──────────────────────────────────────────────────────────────────

setup_worktree() {
    git -C "${REPO_ROOT}" fetch "${UPSTREAM_REMOTE}" "${UPSTREAM_BRANCH}" --quiet
    rm -rf "${WORKTREE_DIR}"
    git -C "${REPO_ROOT}" worktree add --quiet \
        --track -b "_kotoba-sync-$$" "${WORKTREE_DIR}" \
        "${UPSTREAM_REMOTE}/${UPSTREAM_BRANCH}"
}

teardown_worktree() {
    local branch
    branch="$(git -C "${WORKTREE_DIR}" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
    git -C "${REPO_ROOT}" worktree remove --force "${WORKTREE_DIR}" 2>/dev/null || true
    if [[ -n "${branch}" && "${branch}" == _kotoba-sync-* ]]; then
        git -C "${REPO_ROOT}" branch -D "${branch}" 2>/dev/null || true
    fi
}

patch_cargo_for_upstream() {
    local file="$1"
    sed -i '' \
        -e "s|license = \"${MONOREPO_LICENSE}\"|license = \"${UPSTREAM_LICENSE}\"|" \
        -e "s|authors = \[${MONOREPO_AUTHORS}\]|authors = [${UPSTREAM_AUTHORS}]|" \
        "${file}"
    # Insert repository line if not present
    if ! grep -q 'repository = ' "${file}"; then
        sed -i '' "/^authors = /a\\
${UPSTREAM_REPO}" "${file}"
    fi
}

patch_cargo_for_monorepo() {
    local file="$1"
    sed -i '' \
        -e "s|license = \"${UPSTREAM_LICENSE}\"|license = \"${MONOREPO_LICENSE}\"|" \
        -e "s|authors = \[${UPSTREAM_AUTHORS}\]|authors = [${MONOREPO_AUTHORS}]|" \
        -e "/^${UPSTREAM_REPO//\//\\/}/d" \
        "${file}"
}

# ── push ─────────────────────────────────────────────────────────────────────

cmd_push() {
    local msg="${1:-sync: update from monorepo $(git -C "${REPO_ROOT}" rev-parse --short HEAD)}"

    echo "→ Setting up worktree for ${UPSTREAM_REMOTE}/${UPSTREAM_BRANCH} …"
    setup_worktree
    trap 'teardown_worktree' EXIT

    echo "→ Rsyncing source (excluding monorepo-only files) …"

    # Build rsync exclude args
    local excludes=()
    for item in "${MONOREPO_ONLY[@]}"; do
        excludes+=(--exclude="${item}")
    done
    excludes+=(--exclude="target/")
    excludes+=(--exclude=".git")    # covers both .git file (worktree) and .git dir
    excludes+=(--exclude="scripts/sync-upstream.sh")  # this script is monorepo-only

    rsync -a --delete "${excludes[@]}" "${KOTOBA_DIR}/" "${WORKTREE_DIR}/"

    # Patch Cargo.toml for upstream
    patch_cargo_for_upstream "${WORKTREE_DIR}/Cargo.toml"

    # Check for differences (tracked + untracked)
    if [[ -z "$(git -C "${WORKTREE_DIR}" status --porcelain)" ]]; then
        echo "→ No changes to push."
        return 0
    fi

    git -C "${WORKTREE_DIR}" add -A
    git -C "${WORKTREE_DIR}" diff --cached --stat

    echo "→ Committing: ${msg}"
    git -C "${WORKTREE_DIR}" \
        -c user.name="Jun Kawasaki" \
        -c user.email="j.kawasaki@gftd.co.jp" \
        commit -m "${msg}"

    echo "→ Pushing to ${UPSTREAM_REMOTE}/${UPSTREAM_BRANCH} …"
    git -C "${WORKTREE_DIR}" push "${UPSTREAM_REMOTE}" "HEAD:${UPSTREAM_BRANCH}"
    echo "✓ Pushed to https://github.com/etzhayyim/kotoba"
}

# ── pull ─────────────────────────────────────────────────────────────────────

cmd_pull() {
    echo "→ Fetching ${UPSTREAM_REMOTE}/${UPSTREAM_BRANCH} …"
    git -C "${REPO_ROOT}" fetch "${UPSTREAM_REMOTE}" "${UPSTREAM_BRANCH}" --quiet
    setup_worktree
    trap 'teardown_worktree' EXIT

    echo "→ Rsyncing from upstream into monorepo (preserving monorepo-only files) …"

    # Build rsync exclude args — keep monorepo-only files untouched
    local excludes=()
    for item in "${MONOREPO_ONLY[@]}"; do
        excludes+=(--exclude="${item}")
    done
    excludes+=(--exclude="target/")
    excludes+=(--exclude=".git")
    excludes+=(--exclude="scripts/sync-upstream.sh")

    rsync -a --delete "${excludes[@]}" "${WORKTREE_DIR}/" "${KOTOBA_DIR}/"

    # Patch Cargo.toml back to monorepo values
    patch_cargo_for_monorepo "${KOTOBA_DIR}/Cargo.toml"

    echo "→ Changes in monorepo after pull:"
    git -C "${REPO_ROOT}" diff --stat -- "60-apps/ai-gftd-project-kotoba/" | head -20 || true
    echo "✓ Pull complete. Review changes and commit to the monorepo manually."
}

# ── dispatch ─────────────────────────────────────────────────────────────────

CMD="${1:-}"
shift || true

case "${CMD}" in
    push) cmd_push "$@" ;;
    pull) cmd_pull ;;
    *)
        echo "Usage: $(basename "$0") push [commit-message]"
        echo "       $(basename "$0") pull"
        exit 1
        ;;
esac
