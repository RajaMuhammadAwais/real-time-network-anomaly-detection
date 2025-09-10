#!/usr/bin/env bash
set -euo pipefail

# Script: push_pr_branch.sh
# Purpose: Commit current changes, create a new branch, push to origin, and optionally open a PR (via gh CLI)

BRANCH_PREFIX="${BRANCH_PREFIX:-devops-contrib-setup}"
BRANCH_NAME="${BRANCH_NAME:-${BRANCH_PREFIX}-$(date +%Y%m%d-%H%M%S)}"
COMMIT_MSG=${COMMIT_MSG:-"chore: add DevOps (Docker/CI) and contributor setup (templates, CoC, security)"}
TARGET_BASE=${TARGET_BASE:-"main"}

# Check git
if ! command -v git >/dev/null 2>&1; then
  echo "git is required. Please install git."
  exit 1
fi

# Ensure we're in a git repo
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "This directory is not a git repository. Initialize it first:"
  echo "  git init"
  echo "  git remote add origin <repo-url>"
  exit 1
fi

# Verify remote exists
if ! git remote get-url origin >/dev/null 2>&1; then
  echo "No 'origin' remote configured. Add it first:"
  echo "  git remote add origin <repo-url>"
  exit 1
fi

# Ensure user identity is configured
if ! git config user.name >/dev/null || ! git config user.email >/dev/null; then
  echo "Git user identity not configured. Configure it before proceeding:"
  echo "  git config --global user.name \"Your Name\""
  echo "  git config --global user.email \"you@example.com\""
  exit 1
fi

# Fetch latest
git fetch origin

# Create branch from base
git checkout -B "${BRANCH_NAME}" "origin/${TARGET_BASE}" || git checkout -b "${BRANCH_NAME}"

# Stage and commit changes (if any)
if ! git diff --quiet || ! git diff --cached --quiet; then
  git add -A
  git commit -m "${COMMIT_MSG}" || true
else
  echo "No changes to commit. Creating/pushing branch anyway."
fi

# Push branch
git push -u origin "${BRANCH_NAME}"

echo "Branch pushed: ${BRANCH_NAME}"

# Try to open PR using GitHub CLI if available
if command -v gh >/dev/null 2>&1; then
  echo "Attempting to create PR via GitHub CLI..."
  gh pr create --base "${TARGET_BASE}" --head "${BRANCH_NAME}" \
    --title "DevOps + Contributor setup" \
    --body "This PR introduces Docker/Compose, CI (lint/test/build), code quality configs, and contributor docs/templates."
  echo "PR created."
else
  echo "GitHub CLI (gh) not found. You can install it: https://cli.github.com/"
  echo "Or open a PR manually from: https://github.com/$(git remote get-url origin | sed -E 's#(git@github.com:|https://github.com/)([^/.]+/[^/.]+)(\\.git)?#\\2#')/compare/${TARGET_BASE}...${BRANCH_NAME}?expand=1"
fi