# Case study: building an OIDC provider you're not supposed to build

> **Status: in progress** — grows as the project does. Milestone 1 (the provider itself)
> is done; MoneyTrckr migration and Portal integration will extend this document.

## The problem

By Phase 3 the ecosystem had three apps with a fourth coming, each needing accounts.
MoneyTrckr shipped with its own JWT auth behind an `IdentityProvider` interface —
deliberately swappable. Duplicating login, password storage, and session policy per app
is how real orgs end up with five password databases; the fix is the same one real orgs
use: one identity provider, every app an OIDC client.

## The decision everyone warns you about

"Never build your own auth" is correct advice, and this project respects the reason
behind it rather than the slogan. The risk in DIY auth is hand-rolled protocol flows and
crypto. So the protocol and crypto are **Spring Authorization Server's** — the same
RFC implementations (6749, 7636, OIDC Core) that back real products. What I built is the
policy shell around it:

| Framework owns | This codebase owns |
|---|---|
| Authorization code + PKCE flow mechanics | Which flows are allowed at all (code+PKCE, nothing else) |
| Token signing/validation (Nimbus JOSE) | Key storage, rotation cadence, kid pinning |
| Client authentication | Client registration policy, secret lifecycle |
| OIDC discovery / userinfo / logout endpoints | Claims design (groups, per-app roles), invite gate, audit |

**Alternatives considered:** Keycloak (near-zero code — but the goal was to *understand*,
and operating Keycloak teaches ops, not protocol); fully hand-rolled (maximum learning,
irresponsible for anything internet-facing — rejected).

## Threat model (v1)

Assets: user credentials, sessions/tokens, the invite gate, the audit trail.

| Threat | Mitigation |
|---|---|
| Credential stuffing / brute force | argon2id (memory-hard), per-user+IP sliding-window rate limit, audit of every failure |
| Authorization code interception | PKCE required for **every** client, exact redirect URI matching (SAS) |
| Token theft → long-lived access | 10-minute access tokens; refresh rotation with reuse rejection |
| DB leak → usable invites | invites stored as SHA-256 only; 256-bit random tokens |
| DB leak → offline password cracking | argon2id with Spring Security 5.8 defaults |
| Signing key compromise | 30-day rotation; keys never leave the isolated auth DB; old keys retired on schedule |
| Registration abuse | no open registration — invite tokens with expiry + max-uses + revocation, every redemption audited |
| Admin API abuse | separate stateless chain, bearer-only (no cookies → no CSRF surface), `admin` group claim required, self-demotion refused |
| Session fixation / CSRF on login pages | Spring Security defaults: session migration, CSRF tokens on all forms |

Accepted trade-offs (documented, revisited later): in-memory rate limiter resets on
restart (single instance); no MFA in v1 (TOTP is on the backlog); private keys stored
as PEM in the isolated DB rather than an HSM (cost boundary: this runs on a €6.49/mo VPS).

## Interesting problems along the way

**JWKS rotation vs. a picky encoder.** Publishing old keys for verification while signing
with the newest sounds trivial — until `NimbusJwtEncoder` refuses to choose among multiple
matching keys. Pinning the active `kid` in the JWS header via the token customizer keeps
selection deterministic while the JWKS document carries every still-relevant key.

**The Jackson allowlist ambush.** `JdbcOAuth2AuthorizationService` round-trips token claims
through Jackson with Spring Security's deserialization allowlist. `List.copyOf()` in the
claims customizer produced `ImmutableCollections$List12` — serialized fine, then blew up
at the userinfo endpoint days-of-debugging later. Caught in an integration test instead:
the suite drives the *entire* flow (login → authorize → token → userinfo → refresh →
reuse-rejection), not just the happy path of each endpoint.

**Consent as policy, not ceremony.** All clients are first-party, so the consent screen is
disabled per client (`requireAuthorizationConsent(false)`) — one less dark pattern, one
less page to maintain. The setting is per-client, so a future third-party client flips it
back on.

## Results

- Full OIDC provider: discovery, JWKS with rotation, code+PKCE, userinfo, RP-initiated logout.
- 12 tests including an end-to-end protocol drive with negative cases
  (PKCE-less authorize rejected, rotated refresh token reuse rejected, dead invites refused).
- Invite lifecycle with complete audit: mint → share → redeem → revoke, every step logged.

## Next

- Demo client app → prove the integration path.
- MoneyTrckr migration off local JWT (retires its interim edge-key gate).
- Single sign-out across apps (locked into scope for v1 of the migration).
- Portal admin UI consuming the headless API.
