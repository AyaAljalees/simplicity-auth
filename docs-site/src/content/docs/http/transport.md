---
title: HTTP transport
description: Mount the full sign-in surface — OTP, dev-OTP, and OIDC — as framework-agnostic Web-standard handlers, instead of hand-writing routes, cookies, and the OIDC login-state.
---

`@smplcty/auth/http` is the **transport tier**. The core library gives you
primitives — the [method router](/simplicity-auth/methods/overview/), the
[OIDC handler](/simplicity-auth/methods/oidc/), the
[session lifecycle](/simplicity-auth/sessions/lifecycle/). This subpath wires
them into ready-made HTTP endpoints so an app doesn't re-implement the `/auth/*`
routes, the session cookie, the signed OIDC login-state cookie, and the
per-request auth middleware.

Every handler is a Web-standard `(Request) => Promise<Response>`, so it mounts
**directly** in Hono and Next.js App Router — no adapter. Twilio and
`oauth4webapi` stay [optional peers](/simplicity-auth/getting-started/installation/):
you pass the handlers you constructed via config, so the transport tier adds no
new heavy dependency (it's built on Web `Request`/`Response` and Web Crypto).

## What an app still owns

After mounting this, the only auth code an app writes is:

1. **Config** — its pool, cookie policy, a tenant-slug resolver (Host parsing is
   deployment-specific), and — opt-in — the OTP and/or OIDC handlers.
2. **The sign-in screen** — presentation only; it calls `GET …/sign-in/options`
   and renders the IdP buttons + an OTP form.
3. **Its authorization scope + RLS policies** — the app's domain model.
4. **Seed rows** — its tenants, `auth_domains`, service principals.

Everything else — OTP send/verify, dev-OTP fallback, OIDC
initiate/callback/token-exchange, session mint + cookie, login-state cookie,
per-request session→GUCs→RLS — comes from the library.

## Set up

```ts
import { createAuthHandlers } from '@smplcty/auth/http';
import { oidcHandler } from '@smplcty/auth/oidc';
import { twilioVerifyHandler } from '@smplcty/auth/twilio';
import { createTwilioVerifyClient } from '@smplcty/twilio';

const handlers = createAuthHandlers({
  pool,
  cookie: { name: 'app_session', domain: '.app.example.com' },
  loginStateSecret: process.env.LOGIN_STATE_SECRET!,
  // Host → tenant slug (deployment-specific).
  tenantSlugFromRequest: (req) => new URL(req.url).hostname.split('.')[0] ?? null,
  // Opt-in user-bound OTP. Omit for an SSO-only product.
  otpHandler: twilioVerifyHandler({ client: createTwilioVerifyClient(twilioCfg) }),
  // Opt-in org-bound OIDC. The client secret comes from YOUR secret store, never the DB.
  oidc: oidcHandler({ clientSecret: (ad) => secrets.get(ad.tenantId) }),
});
```

### Mount in Hono

```ts
// One line: the dispatcher matches the known auth routes by method + path suffix.
app.all('/auth/*', (c) => handlers.handle(c.req.raw).then((res) => res ?? c.notFound()));
```

### Mount in Next.js (App Router)

```ts
// app/auth/[...auth]/route.ts — the handlers ARE Web-standard route handlers.
import { createAuthHandlers } from '@smplcty/auth/http';
const handlers = createAuthHandlers(/* … */);
export const GET = (req: Request) => handlers.handle(req).then((r) => r ?? new Response(null, { status: 404 }));
export const POST = GET;
```

Or wire individual endpoints as explicit routes (`export const GET = handlers.signInOptions`).

## Endpoints

Paths are shown relative to your mount base (e.g. `/auth`). `handle(request)`
dispatches by **method + path suffix** (so it's robust to whatever prefix the
app mounts under) and returns `null` when nothing matches, letting the host
fall through.

| Method & path | Purpose | Request | Response |
| --- | --- | --- | --- |
| `GET …/sign-in/options` | What the sign-in screen renders for this tenant. | tenant from `tenantSlugFromRequest` | `{ tenantId, otpAllowed, authDomains: [{ authDomainId, displayName, integrationType }] }` |
| `POST …/otp/initiate` | Send an OTP. | `{ identifier }` | `{ otpSent: true }` |
| `POST …/otp/complete` | Verify an OTP, mint a session. | `{ identifier, credential, returnTo? }` | `200` + session cookie, `{ ok: true, returnTo }` |
| `GET …/oidc/start?authDomainId=&returnTo=` | Begin OIDC: redirect to the IdP. | query params | `302` to the IdP + a signed login-state cookie |
| `GET …/oidc/callback` | Finish OIDC: verify, mint a session. | provider's `?code&state` + login-state cookie | `302` to `returnTo` + session cookie |
| `POST …/sign-out` | Revoke the session, clear the cookie. | session cookie / bearer | `200` + cleared cookie |
| `GET …/session` | The current identity context. | session cookie / bearer | `{ authenticated, userId, activeRole, roles, privileges }` or `401` |

`integration_params` (issuer/clientId) are **not** included in
`sign-in/options` — the screen only needs the id, label, and type.

## The sign-in flow

```text
                    GET /auth/sign-in/options        → { authDomains[], otpAllowed }
 sign-in screen ───────────────────────────────────────────────────────────────────►
        │
        ├─ user picks an IdP button ──► GET /auth/oidc/start?authDomainId=ID
        │                                    └─► 302 to IdP ──► IdP ──► GET /auth/oidc/callback
        │                                                                   └─► 302 home + session
        │
        └─ user enters email/phone ───► POST /auth/otp/initiate { identifier }
                                          POST /auth/otp/complete { identifier, credential }
                                              └─► 200 + session
```

The chooser logic the screen renders from `sign-in/options`: **0 IdPs** → OTP
form only; **1 IdP** → a single button (or auto-start); **N IdPs** → one button
per IdP. The OTP form shows when `otpAllowed` is true (an OTP handler is
configured). Addresses at a verified email domain that requires SSO are
**refused server-side** in the OTP endpoints, on every sub-domain, so a crafted
request can't bypass it. See [Email domains](/simplicity-auth/methods/email-domains/).

## Cookies

Two cookies, both built from Web standards (no `Buffer`; edge-safe):

- **Session cookie** (`cookie.name`) — carries the raw opaque session token.
  `HttpOnly`, `Secure` (default), `SameSite=Lax`, `Path=/`. Set `cookie.domain`
  to a parent domain (e.g. `.app.example.com`) to share the session across
  tenant sub-domains. `Max-Age` defaults to 30 days (`cookie.maxAgeSeconds`);
  the **authoritative** expiry is server-side on the `sessions` row.
- **OIDC login-state cookie** (`<name>_oidc`) — short-lived (`loginStateTtlSeconds`,
  default 600s), **HMAC-signed** with `loginStateSecret`. Holds the
  `auth_domains` id plus the PKCE `state`/`nonce`/`codeVerifier` the OIDC handler
  produced, so the callback can complete the flow. `SameSite=Lax` so it survives
  the top-level GET redirect back from the IdP. Verified constant-time and
  freshness-checked; cleared after callback.

The signing helpers are exported if you need them directly:
`serializeCookie`, `parseCookies`, `signLoginState`, `verifyLoginState`.

## Per-request authentication

Use these in your own middleware / loaders to authenticate every other request:

```ts
import { getSessionToken, withRequestSession } from '@smplcty/auth/http';

// Read the raw token from the cookie or `Authorization: Bearer`.
const token = getSessionToken(request, config); // string | null

// Resolve + validate the session, set identity GUCs, run the app scope hook,
// and run your code under RLS — the request-shaped wrapper around withSession.
const data = await withRequestSession(request, config, async (client, ctx) => {
  // ctx = { userId, activeRole, roles, privileges }
  const { rows } = await client.query('SELECT * FROM widgets'); // RLS-scoped
  return rows;
}, { roleName: 'user' });
```

`withRequestSession` rejects with the same
[`withSession` errors](/simplicity-auth/sessions/with-session/)
(`SessionNotFoundError`, `SessionExpiredError`, `RoleNotHeldError`), plus
`SessionNotFoundError` when the request carries no token.

## Configuration

| Field | Required | Purpose |
| --- | --- | --- |
| `pool` | ✓ | The RLS `pg.Pool` used for sessions, the method router, and OIDC. |
| `cookie.name` | ✓ | Session cookie name. |
| `cookie.domain` | | Parent domain for sub-domain session sharing. |
| `cookie.sameSite` / `secure` / `path` / `maxAgeSeconds` | | Cookie attributes (defaults: `lax` / `true` / `/` / 30 days). |
| `loginStateSecret` | ✓ | HMAC secret for the OIDC login-state cookie. |
| `tenantSlugFromRequest` | ✓ | Resolve the tenant slug from the request (e.g. parse the Host). |
| `otpHandler` | | The user-bound OTP handler. Omit for SSO-only. |
| `oidc` | | The `oidcHandler`. Omit if the app has no OIDC. |
| `scope` | | App-owned intra-tenant scope hook (applied by `withRequestSession` and `GET …/session`). |
| `sessionTtl` | | Session lifetime, a Postgres interval. Default `'30 days'`. |
| `loginStateTtlSeconds` | | OIDC login-state cookie lifetime. Default `600`. |
| `returnToDefault` | | Post-sign-in redirect when no safe `returnTo` is given. Default `'/'`. |
| `signInErrorPath` | | Where a failed OIDC start or callback sends the browser, with `?error=<CODE>` appended. Must be a path on this site. Omit to answer those failures with JSON. |
| `sessionMeta` | | Derive IP/geo for the `sessions` row from the request. |
| `logger` | | Passed through to `withSession`. |

## Security

- **Open-redirect guard** — `returnTo` is honored only when it's a same-origin
  relative path; absolute URLs, protocol-relative `//host`, and the backslash
  variant `/\host` (which browsers normalize to `//host`) fall back to
  `returnToDefault`.
- **Signed login-state** — HMAC-SHA256, constant-time verify, freshness-checked;
  a tampered or stale cookie is rejected (the callback returns `400`, or redirects
  to `signInErrorPath` with `INVALID_LOGIN_STATE` when that is set).
- **SSO-required email domains enforced server-side**, on every sub-domain, not
  just hidden in the UI.
- **Cookies** are `HttpOnly` + `Secure` + `SameSite=Lax`; the session token is a
  256-bit opaque value whose hash is all that's stored.
- **Error mapping is opaque** — handlers map known auth errors to status codes
  (`400`/`401`/`403`) with generic messages and never leak internals (unknown
  errors become a bare `500`).

See the [security model](/simplicity-auth/security/) for the library-wide
guarantees.
