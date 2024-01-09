#!/usr/bin/env bash

set -uex

function sync() {
    local OWNER=$1
    local REPO=$2
    local BRANCH=$3
    local DIR=$4
    local SHA
    SHA=$(gh api --jq '.commit.sha' "repos/$OWNER/$REPO/branches/$BRANCH")

    rm -rf "$DIR"
    mkdir -p "$DIR"
    curl -sSL "https://github.com/$OWNER/$REPO/archive/$SHA.tar.gz" | tar xz -C "$DIR" --strip=1

    git add "$DIR"
    git diff --cached --exit-code --quiet || git commit --no-verify -m "sync test cases with https://github.com/$OWNER/$REPO/commit/$SHA"
}

# sync with https://github.com/ietf-jose/cookbook
sync ietf-jose cookbook master testdata/ietf-jose-cookbook

# sync with https://github.com/cose-wg/Examples
sync cose-wg Examples master cose/testdata/cose-wg-examples
