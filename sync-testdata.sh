#!/usr/bin/env bash

set -uex

# sync with https://github.com/ietf-jose/cookbook
OWNER=ietf-jose
REPO=cookbook
SHA=$(gh api --jq '.commit.sha' "repos/$OWNER/$REPO/branches/master")

rm -rf testdata/ietf-jose-cookbook
mkdir -p testdata/ietf-jose-cookbook
curl -sSL "https://github.com/$OWNER/$REPO/archive/$SHA.tar.gz" | tar xz -C testdata/ietf-jose-cookbook --strip=1

git add testdata
git commit -m "sync test cases with https://github.com/$OWNER/$REPO/commit/$SHA"
