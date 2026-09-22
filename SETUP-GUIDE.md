# Skylark MSP Knowledge Hub - Cloudflare Worker Setup

## 1. Repository structure

Replace the old Vercel-style backend files with:

```text
msp-knowledge-api/
├── src/
│   └── worker.js
├── wrangler.jsonc
├── package.json
├── .gitignore
└── README.md
```

Do not commit `.env`, `.dev.vars`, client secrets, access tokens, or other secrets.

## 2. Cloudflare deployment

In Cloudflare:

Workers & Pages -> Create application -> Import an existing Git repository -> select `Skylark-MSP/msp-knowledge-api`.

Project name: `skylark-msp-knowledge-api`

Build command: leave blank.

Deploy command: `npx wrangler deploy` (default).

The repository contains `wrangler.jsonc`, so Workers Builds can use that configuration as the source of truth.

## 3. Get the Worker URL

Cloudflare will provide a `workers.dev` URL, such as:

`https://skylark-msp-knowledge-api.<account>.workers.dev`

The OAuth callback will be:

`https://skylark-msp-knowledge-api.<account>.workers.dev/auth/callback`

## 4. GitHub App callback URL

Open the `Skylark MSP Knowledge Hub` GitHub App -> General -> Callback URL and set the exact Worker callback URL. Disable wildcard matching if GitHub shows that option.

Keep user authorization enabled via the web flow; the portal starts the flow with `/auth/login`.

## 5. GitHub App permissions

Repository permissions:
- Contents: Read-only

Organization permissions:
- Members: Read-only

Install the App on `Skylark-MSP` with only these repositories:
- `l1-knowledge-base`
- `l2-knowledge-base`
- `shared-knowledge-base`

Do not install it on the portal or API repositories.

## 6. Cloudflare variables and secrets

Variables:

`GITHUB_ORG=Skylark-MSP`

`FRONTEND_ORIGIN=https://skylark-msp.github.io`

`FRONTEND_URL=https://skylark-msp.github.io/msp-knowledge-hub`

`KB_REPOS=l1-knowledge-base,l2-knowledge-base,shared-knowledge-base`

Secrets:

`GITHUB_APP_CLIENT_ID=<GitHub App Client ID>`

`GITHUB_APP_CLIENT_SECRET=<GitHub App Client Secret>`

`STATE_SECRET_HEX=<64 hex chars>`

`SESSION_SECRET_HEX=<64 hex chars>`

Generate the last two locally:

`openssl rand -hex 32`

Run it twice and use different values.

## 7. Frontend

Update `msp-knowledge-hub/index.html` so the API base points at the Worker URL and requests use `credentials: 'include'`. The browser must never receive the GitHub App client secret or GitHub access token.

## 8. User flow

1. User opens the GitHub Pages portal.
2. User clicks Sign in with GitHub.
3. Worker redirects to GitHub.
4. User authenticates and authorizes the GitHub App.
5. GitHub redirects to `/auth/callback`.
6. Worker exchanges the code for a GitHub App user access token.
7. Worker verifies active `Skylark-MSP` membership.
8. Worker stores an encrypted short-lived session in an HttpOnly cookie.
9. Portal lists only repositories the signed-in user can read.
10. PDFs are retrieved through the Worker and displayed inside the portal.

## 9. Security notes

- Never put `GITHUB_APP_CLIENT_SECRET` in the frontend.
- Never put GitHub access tokens in the URL, localStorage, or sessionStorage.
- Keep the GitHub App limited to the three KB repositories.
- Keep the GitHub organization base repository permission at `No permission` so repository access is explicit.
