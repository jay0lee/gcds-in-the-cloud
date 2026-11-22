#!/usr/bin/env bash
# Publishes ./wiki/*.md to https://github.com/jay0lee/gcds-in-the-cloud.wiki.git
# Prerequisite: Click "Create the first page" -> "Save Page" once at
#   https://github.com/jay0lee/gcds-in-the-cloud/wiki
# so GitHub provisions the underlying .wiki.git repository.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WIKI_REMOTE="${WIKI_REMOTE:-https://github.com/jay0lee/gcds-in-the-cloud.wiki.git}"
TMP_WIKI="$(mktemp -d)"
trap 'rm -rf "${TMP_WIKI}"' EXIT

echo "Cloning ${WIKI_REMOTE}..."
git clone "${WIKI_REMOTE}" "${TMP_WIKI}"

cp "${REPO_ROOT}"/wiki/*.md "${TMP_WIKI}/"
cd "${TMP_WIKI}"
git add *.md
if git diff --cached --quiet; then
  echo "Wiki is already up to date."
  exit 0
fi

git commit -m "Publish GCDS-in-the-Cloud migration and AD connectivity guides"
git push origin HEAD
echo "Published all Wiki pages to https://github.com/jay0lee/gcds-in-the-cloud/wiki"
