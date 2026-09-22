# Skylark MSP Knowledge API (Cloudflare Worker)

This Worker securely authenticates Skylark MSP users with the GitHub App and serves only documents from repositories the authenticated user can access.

## Routes

- `GET /auth/login`
- `GET /auth/callback`
- `POST /auth/logout`
- `GET /api/me`
- `GET /api/repositories`
- `GET /api/tree?repo=<repo>`
- `GET /api/file?repo=<repo>&path=<path>`

## Required secrets

- `GITHUB_APP_CLIENT_ID`
- `GITHUB_APP_CLIENT_SECRET`
- `STATE_SECRET_HEX`
- `SESSION_SECRET_HEX`

Generate the 32-byte hex secrets locally with:

`openssl rand -hex 32`

## Required variables

- `GITHUB_ORG=Skylark-MSP`
- `FRONTEND_ORIGIN=https://skylark-msp.github.io`
- `FRONTEND_URL=https://skylark-msp.github.io/msp-knowledge-hub`
- `KB_REPOS=l1-knowledge-base,l2-knowledge-base,shared-knowledge-base`
