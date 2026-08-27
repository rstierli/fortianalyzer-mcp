#!/bin/bash
# bootstrap-claude-tooling.sh — restores this repo's Claude Code guardrail
# setup (CLAUDE.md, SKILL.md, .claude/hooks, .claude/skills) from a private
# companion source.
#
# Why this exists: .claude/, CLAUDE.md and SKILL.md are all gitignored in
# this repo (see .gitignore) so that internal AI-agent tooling and process
# notes stay out of this public MIT-licensed project. That means a fresh
# clone has none of it - no session guardrails, no golden-rules reminder,
# no secret-display/destructive-action hooks. This script is the fix: it is
# itself tracked (not gitignored, safe to publish - it contains no secrets
# and no internal process detail, just a copy step) and pulls the actual
# content from a private source that only exists on machines Roland has
# set up for this. 2026-08-27, prompted by wanting to work on this repo
# from more than one machine/session independently of the homelab repo.
#
# External contributors: this is expected to no-op for you. If you don't
# have the private source, the script prints a message and exits 0 - it
# is not part of the actual project setup (see docs/SETUP_GUIDE.md for that).
#
# Usage: ./scripts/bootstrap-claude-tooling.sh [--force]
#   --force   overwrite an existing local .claude/settings.local.json too
#             (default: leave it alone if present, so local customizations
#             like personal Bash permission allowlist entries survive)
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
# Derive from the git remote, not the local directory name - a clone into a
# custom-named folder (e.g. a personal fork checked out as "my-fmg-fork")
# would otherwise silently fail to find its canonical source.
REPO_NAME="$(git -C "$REPO_ROOT" remote get-url origin 2>/dev/null | sed -E 's#.*/##; s#\.git$##')"
[ -z "$REPO_NAME" ] && REPO_NAME="$(basename "$REPO_ROOT")"
SRC="${CLAUDE_TOOLING_SRC:-$HOME/03_Privat/myGITprivate/homelab/claude-tooling/$REPO_NAME}"
FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

if [ ! -d "$SRC" ]; then
  echo "No private Claude-tooling source found at: $SRC"
  echo "(Set CLAUDE_TOOLING_SRC to point elsewhere, or skip this - it's optional.)"
  exit 0
fi

echo "Restoring Claude Code tooling for $REPO_NAME from $SRC ..."

cp "$SRC/CLAUDE.md" "$REPO_ROOT/CLAUDE.md"
cp "$SRC/SKILL.md" "$REPO_ROOT/SKILL.md"

mkdir -p "$REPO_ROOT/.claude/hooks" "$REPO_ROOT/.claude/skills"
cp "$SRC/.claude/hooks/"*.sh "$REPO_ROOT/.claude/hooks/"
chmod +x "$REPO_ROOT/.claude/hooks/"*.sh
cp "$SRC/.claude/skills/"*.md "$REPO_ROOT/.claude/skills/"

if [ ! -f "$REPO_ROOT/.claude/settings.local.json" ] || [ "$FORCE" -eq 1 ]; then
  cp "$SRC/.claude/settings.local.json.template" "$REPO_ROOT/.claude/settings.local.json"
  echo "  settings.local.json installed"
else
  echo "  settings.local.json already exists locally - left untouched (use --force to overwrite)"
fi

echo "Done. CLAUDE.md, SKILL.md, .claude/hooks, .claude/skills restored."
echo "Note: .claude/memory is NOT restored - that's per-machine working state, starts fresh here."
