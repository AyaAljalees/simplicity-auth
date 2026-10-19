---
title: OIDC
description: The @smplcty/auth/oidc handler — authorization-code + PKCE + token exchange + id_token verification on oauth4webapi.
---

The org-bound OIDC handler (opt-in subpath `@smplcty/auth/oidc`) is built on
[`oauth4webapi`](https://github.com/panva/oauth4webapi). Two phases:

```ts
import { oidcHandler } from '@smplcty/auth/oidc'; // optional peer: oauth4webapi

const oidc = oidcHandler({
  // confidential client secret, from YOUR secret store (not auth_domains):
  clientSecret: (authDomain) => secrets.get(authDomain.tenantId),
  // optional: provision a user when a verified identity has no communication method
  provisionUser: async ({ db, authDomain, claims }) => {
    /* create user + email method + default roles for authDomain.tenantId */
  },
});

// Phase 1 — discovery + PKCE/state/nonce → redirect URL + login state:
const { redirectUrl, loginState } = await oidc.initiate(authDomain);
// persist loginState in a short-lived signed cookie keyed by loginState.state, then redirect.

// Phase 2 — on the provider callback (hand back the stored loginState + the callback URL):
const user = await oidc.complete({ db: pool, authDomain, callbackUrl, loginState });
// → { userId, userCommunicationMethodId } — then createSession(...)
```

## What the library does vs what you do

- **`oauth4webapi` (in the handler):** discovery, the authorization URL, PKCE,
  `state`/`nonce`, the code→token exchange, and `id_token` verification
  (signature via JWKS, `iss`/`aud`/`exp`/`nonce`).
- **You (the app):** persist `loginState` (`state` / `nonce` / `codeVerifier`)
  across the redirect in a short-lived signed cookie, and own the callback
  route. The library holds no pre-auth state.

## `auth_domains` config

`integration_params` holds **only public** values:

```json
{ "issuer": "https://login.microsoftonline.com/<tenant-guid>/v2.0", "clientId": "<app-registration-id>" }
```

The **`client_secret` lives in your secret store** (passed via the `clientSecret`
resolver), **not** in the database. Email is read as `email ?? preferred_username`
(Entra often uses the latter) — ensure the user's `user_communication_methods.code`
(channel `email`) matches.

`complete` refuses an address at a domain the auth domain's tenant hasn't
verified, with `EmailDomainNotVerifiedError`, before any lookup or
`provisionUser` call. An auth domain with no verified domains signs nobody in.
See [Email domains](/simplicity-auth/methods/email-domains/).

## Why not Auth.js, why not a hand-rolled `@smplcty/oidc`

`oauth4webapi` is the spec-complete protocol engine (the same one Auth.js uses
internally), framework-agnostic, and fits per-tenant config and our sessions +
RLS without a parallel session model. See
[ADR-0001](/simplicity-auth/design/adr-0001/) for the full rationale (and why
`@smplcty/oidc` was deprecated).
