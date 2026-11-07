#!/bin/sh
# Pre-commit: format, lint, and block accidental secrets.
# I run the secret scan last because it is the slowest, and I only scan staged files so
# a big repo does not make every commit take 10 seconds.
set -e
files=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(py|ts|go)$' || true)
[ -z "$files" ] && exit 0
ruff format --check $files
ruff check $files
# Refuse the commit if anything looks like a credential; false positives are cheaper
# than a leaked key.
if git diff --cached | grep -E 'AKIA[0-9A-Z]{16}|-----BEGIN (RSA|OPENSSH) PRIVATE' >/dev/null; then
  echo "possible secret in staged changes; aborting" >&2
  exit 1
fi
