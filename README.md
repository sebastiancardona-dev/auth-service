# auth-service

Self-built **OAuth2 / OIDC identity provider** for the [sebastiancardona.dev](https://sebastiancardona.dev)
ecosystem. One account works across every app; registration is gated by invite tokens
that only the admin can mint.

> **Honesty first:** in production you use Keycloak, Auth0, or your cloud's IdP. I built
> this to understand the protocol deeply — on top of **Spring Authorization Server**, which
> implements the RFCs (6749, 7636 PKCE, OIDC Core). The framework owns the flows and the
> crypto; this codebase owns policy, storage, and UX. The line is deliberate and documented
> in [CASE-STUDY.md](CASE-STUDY.md).

## What it does

- **OIDC provider**: discovery, JWKS, authorization code + PKCE **only** — no implicit,
  no password grant, PKCE required even for confidential clients (RFC 9700).
- **DB-backed JWKS rotation**: a fresh RSA key every 30 days; retiring keys stay published
  until every token they signed has expired. Signing pins the active `kid`.
- **Invite-gated registration**: multi-use tokens (max uses + expiry) that pre-assign a
  group — one link per audience (`recruiter`, `friend`). 256-bit tokens, only the SHA-256
  stored, full audit trail of mints/redemptions/revocations.
- **Groups + per-app roles as claims**: `groups: ["admin"]` ecosystem-wide,
  `roles: {"<client_id>": [...]}` per app. Apps map claims to permissions.
- **Short-lived access tokens (10 min) + rotating refresh tokens** — reuse of a rotated
  refresh token is rejected.
- **argon2id** password hashing, per-user+IP login rate limiting, append-only audit log.
- **Headless admin API** (`/api/admin/**`, JWT with `admin` group): users, groups, clients,
  invites, audit. The UI lives in the Portal project.

## Run locally

```bash
# needs Docker (compose Postgres autostarts) and JDK 21
./mvnw spring-boot:run "-Dspring-boot.run.profiles=local"
# → http://localhost:8080  (admin seed: juanse@local.dev / local-admin-password)
```

Tests: `./mvnw verify -Pintegration` (unit + Testcontainers; the integration suite drives
the full PKCE flow end to end, including refresh rotation and negative cases).

## Getting an admin token

The first-party `admin-cli` public client is bootstrap-seeded exactly so an admin can
ever get a token (registering clients needs a token, which needs a client):

```bash
eval "$(python ops/admin-token.py)"        # opens the browser; log in as admin
# → AUTH_ADMIN_TOKEN in your shell for the calls below (10-min lifetime; rerun to refresh)
```

## Registering an app (OIDC client)

```bash
# mint a client (admin token required — see below)
curl -X POST https://auth.sebastiancardona.dev/api/admin/clients \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"clientId":"myapp","name":"My App","confidential":true,
       "redirectUris":["https://myapp.sebastiancardona.dev/login/oauth2/code/ecosystem"]}'
# → returns the client secret EXACTLY ONCE
```

Spring apps integrate with `spring-boot-starter-oauth2-client`; SPAs use code + PKCE
(public client, `"confidential": false`). Discovery document:
`https://auth.sebastiancardona.dev/.well-known/openid-configuration`

## Minting invites

```bash
curl -X POST https://auth.sebastiancardona.dev/api/admin/invites \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"group":"recruiter","ttlDays":30,"maxUses":20,"note":"LinkedIn wave 1"}'
# → { "registerUrl": "https://auth.…/register?invite=<token>" }  (token shown once)
```

## Architecture

```
Spring Boot 3.5 / Java 21 / Spring Authorization Server
├── PostgreSQL (own isolated DB — never shared with apps)
│   ├── users, groups, user_client_roles         ← identity
│   ├── invites, invite_redemptions              ← registration gate + audit
│   ├── audit_events (append-only)               ← every security event
│   ├── signing_keys                             ← JWKS rotation
│   └── oauth2_* (SAS JDBC schema)               ← protocol state
├── Thymeleaf login/register pages (ecosystem design language)
└── /health + /info + Dockerfile + tag→deploy pipeline (ecosystem contracts)
```

Deployed as one image through the ecosystem's
[build-once-promote pipeline](https://github.com/sebastiancardona-dev/workflows):
every push → test env, tags gate through test → GitHub Release → prod with auto-rollback.
