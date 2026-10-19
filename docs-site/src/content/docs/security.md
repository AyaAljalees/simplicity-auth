---
title: Security model
description: The guarantees @smplcty/auth makes.
---

- **Every query is parameterized** — no string interpolation in the library.
- **Session tokens are hashed at rest** (SHA-256). The raw 256-bit token is
  returned once and never stored; a database leak exposes only hashes.
- **Identity GUCs are set via `set_config($1, $2, true)`** — transaction-scoped,
  so injection and cross-request leakage are impossible.
- **`withSession` fails closed** — it validates existence, expiry/revocation,
  and role membership before your callback runs.
- **Force sign-off is a row update** — per-session, per-user, or per-tenant
  (`revokeTenantSessions` spares NULL-wildcard members). Role/privilege changes
  apply on the next request because they're resolved per request, not baked into
  the token.
- **A tenant's IdP vouches only for domains its tenant owns** — the OIDC callback
  refuses an address whose domain the tenant hasn't verified through DNS, before
  any lookup or provisioning. Tenant admins can't mark a domain verified: column
  grants keep `verified_at` and the per-row token out of `app_rls`'s reach.
  See [Email domains](/simplicity-auth/methods/email-domains/).
- **OIDC verification is delegated to `oauth4webapi`** (the spec-complete engine,
  using JWKS); auth core has no `oauth4webapi`/Twilio dependency — method
  handlers are opt-in subpaths with optional peers.
- **Role-aware RLS ships on the identity tables** — `users`, `user_roles`,
  `user_communication_methods`, `tenants`, and `auth_domains` are row-level
  secured out of the box, keyed on the standard `user`/`settings`/`security`
  roles and the user's `user_roles` (no app-specific columns). A plain user sees
  only itself; a `security` admin manages users in tenants it administers; a
  `settings` admin owns `auth_domains` and tenant creation. The bypass pool and
  the `SECURITY DEFINER resolve_session` are unaffected.
- **Privilege escalation is closed at the source** — raw `INSERT` on `users` is
  denied by RLS; provisioning goes through `auth_create_user`, which refuses to
  grant a tenant the caller does not administer (or an all-tenants role without
  global authority). The library owns the grants on its tables too, so a
  consuming app can't silently miss one.
- **Soft-deleted rows stop taking effect immediately** — session resolution and
  user/role lookups exclude `deleted_at IS NOT NULL`.
- **Audit attribution is enforced** — auditable tables' `created_by`/`updated_by`
  are NOT NULL, stamped from `app.actor_id`; background writes run as an audited
  service principal.
