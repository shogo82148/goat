#!/bin/bash
# fetch script for metadata from real world.

ROOT=$(cd "$(dirname "$0")" && pwd)

# GitHub Actions
curl -sSL https://token.actions.githubusercontent.com/.well-known/openid-configuration | jq . > "$ROOT/gha-openid-configuration.json"
curl -sSL https://token.actions.githubusercontent.com/.well-known/jwks | jq . > "$ROOT/gha-jwks.json"

# Google
curl -sSL https://accounts.google.com/.well-known/openid-configuration | jq . > "$ROOT/google-openid-configuration.json"
curl -sSL https://www.googleapis.com/oauth2/v3/certs | jq . > "$ROOT/google-jwks.json"

# Microsoft
curl -sSL https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration | jq . > "$ROOT/microsoft-openid-configuration.json"
curl -sSL https://login.microsoftonline.com/common/discovery/v2.0/keys | jq . > "$ROOT/microsoft-jwks.json"

# Facebook
curl -sSL https://www.facebook.com/.well-known/openid-configuration | jq . > "$ROOT/facebook-openid-configuration.json"
curl -sSL https://www.facebook.com/.well-known/oauth/openid/jwks/ | jq . > "$ROOT/facebook-jwks.json"

# Apple
curl -sSL https://appleid.apple.com/.well-known/openid-configuration | jq . > "$ROOT/apple-openid-configuration.json"
curl -sSL https://appleid.apple.com/auth/keys | jq . > "$ROOT/apple-jwks.json"

# Yahoo! Japan
curl -sSL https://auth.login.yahoo.co.jp/yconnect/v2/.well-known/openid-configuration | jq . > "$ROOT/yahoo-openid-configuration.json"
curl -sSL https://auth.login.yahoo.co.jp/yconnect/v2/jwks | jq . > "$ROOT/yahoo-jwks.json"

# LINE
curl -sSL https://access.line.me/.well-known/openid-configuration | jq . > "$ROOT/line-openid-configuration.json"
curl -sSL https://api.line.me/oauth2/v2.1/certs | jq . > "$ROOT/line-jwks.json"

# Recruit
curl -sSL https://point.recruit.co.jp/.well-known/openid-configuration | jq . > "$ROOT/recruit-openid-configuration.json"
curl -sSL https://point.recruit.co.jp/oidc/certs | jq . > "$ROOT/recruit-jwks.json"

# Slack
curl -sSL https://slack.com/.well-known/openid-configuration | jq . > "$ROOT/slack-openid-configuration.json"
curl -sSL https://slack.com/openid/connect/keys | jq . > "$ROOT/slack-jwks.json"

# PayPal
curl -sSL https://www.paypalobjects.com/.well-known/openid-configuration | jq . > "$ROOT/paypal-openid-configuration.json"
curl -sSL https://api.paypal.com/v1/oauth2/certs | jq . > "$ROOT/paypal-jwks.json"

# Firebase
curl -sSL https://securetoken.google.com/shogo82148/.well-known/openid-configuration | jq . > "$ROOT/firebase-openid-configuration.json"
curl -sSL https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com | jq . > "$ROOT/firebase-jwks.json"

# NIKKEI ID
curl -sSL https://id.nikkei.com/.well-known/openid-configuration | jq . > "$ROOT/nikkei-openid-configuration.json"
curl -sSL https://id.nikkei.com/lounge/ep/connect/2.0/certs | jq . > "$ROOT/nikkei-jwks.json"

# GitLab
curl -sSL https://gitlab.com/.well-known/openid-configuration | jq . > "$ROOT/gitlab-openid-configuration.json"
curl -sSL https://gitlab.com/oauth/discovery/keys | jq . > "$ROOT/gitlab-jwks.json"

# Okta
curl -sSL https://okta.okta.com/.well-known/openid-configuration | jq . > "$ROOT/okta-openid-configuration.json"
curl -sSL https://okta.okta.com/oauth2/v1/keys | jq . > "$ROOT/okta-jwks.json"
