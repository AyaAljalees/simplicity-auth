---
title: Sign-in methods overview
description: Tenant-centric discovery, the OTP path via the router, and OIDC via a dedicated handler.
---

Sign-in is **tenant-centric**: the app resolves the tenant from the request
sub-domain (`tenants.slug`), and the router lists that tenant's IdPs. A tenant
has **0..N** OIDC IdPs (mergers, mixed workforces, multi-domain orgs):

- **0 IdPs** → OTP only.
- **1 IdP** → straight redirect, no chooser.
- **N IdPs** → a chooser (one button per IdP, labeled `displayName`, valued by `auth_domain_id`).

```ts
import { createMethodRouter } from '@smplcty/auth';
import { oidcHandler } from '@smplcty/auth/oidc';
import { twilioVerifyHandler } from '@smplcty/auth/twilio';
import { createTwilioVerifyClient } from '@smplcty/twilio';

const router = createMethodRouter({
  db: pool,
  otpHandler: twilioVerifyHandler({ client: createTwilioVerifyClient(cfg) }),
});
const oidc = oidcHandler({ clientSecret: (ad) => secrets.get(ad.tenantId) });

// Sign-in page — app parsed Host → 'acme':
const opts = await router.signInOptions({ tenantSlug: 'acme' });
// opts = { tenantId, authDomains: AuthDomain[], otpAllowed: boolean }
```

## Two paths

- **OTP / dev-OTP** (user-bound) goes through the **router**: `initiateOtp` /
  `completeOtp`, open on every tenant except for addresses at a verified email
  domain that requires SSO, which the router refuses on every sub-domain (see
  [Email domains](/simplicity-auth/methods/email-domains/)). A handler that
  implements the optional `resolveUser` also lets the router skip sending a
  code to such a user's phone or other email.
- **OIDC** (org-bound) is driven by a **dedicated handler** —
  [`@smplcty/auth/oidc`](/simplicity-auth/methods/oidc/) on `oauth4webapi` — whose
  `initiate`/`complete` shape (PKCE + login-state) is richer than the OTP
  two-phase, so it's not routed through the generic interface.

```ts
// OTP (only when opts.otpAllowed):
await router.initiateOtp({ identifier: phone });
const user = await router.completeOtp({ identifier: phone, credential: code });

// OIDC — user picked an IdP from opts.authDomains:
const { redirectUrl, loginState } = await oidc.initiate(authDomain);
// ...persist loginState, redirect, then on callback:
const user2 = await oidc.complete({ db: pool, authDomain, callbackUrl, loginState });
```

Either path yields a `{ userId, userCommunicationMethodId }`; hand it to
[`createSession`](/simplicity-auth/sessions/lifecycle/).

Auth **core** depends on neither `oauth4webapi` nor Twilio — the handler subpaths
do, as optional peers. A password-only app installs neither.

:::tip[Don't want to wire the routes yourself?]
The [HTTP transport tier](/simplicity-auth/http/transport/)
(`@smplcty/auth/http`) does all of the above — discovery, the OTP two-phase, the
OIDC `start`/`callback`, the session cookie, and the signed login-state cookie —
as framework-agnostic handlers you mount in one line. Drop it in and you only
build the sign-in screen.
:::
