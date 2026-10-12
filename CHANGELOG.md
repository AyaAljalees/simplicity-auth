# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **Closed a gap in the 9.0.0 `search_path` hardening.** The seven
  `SECURITY DEFINER` functions behind the shipped RLS (`auth_has_role`,
  `auth_can_admin_user`, `auth_in_tenant`, `auth_all_tenants`,
  `auth_tenant_ids`, `resolve_session`, `auth_create_user`) pinned
  `search_path` to `pg_catalog, public`. With `pg_temp` left out, Postgres
  searches the caller's temporary tables _first_. Someone able to run SQL as
  your app's database role, through SQL injection or leaked credentials, could
  create a temporary `user_roles` table and make these functions grant them
  any role in every tenant. The 9.0.0 notes said the pin closed this kind of
  attack; it did not fully. The pin is now `pg_catalog, public, pg_temp`,
  which puts temporary tables last, behind the real ones. Normal behavior is
  unchanged, and the next migration applies it with no extra flags. (#16)

### Fixed

- **Sign-in now finds a user's email address in any casing.** Code sign-in and
  OIDC/SSO matching used to compare emails exactly, so `Bob@Acme.com` did not
  reach the user stored as `bob@acme.com`. This mostly affected SSO users,
  because Microsoft Entra often returns mixed-case addresses. Addresses are
  still stored and shown exactly as entered.
- **Two users can no longer hold the same email address in different
  casings.** Before, an admin could add `Bob@Acme.com` next to an existing
  `bob@acme.com`, and which account a person reached depended on how they
  typed their address. Adding a contact method that differs from a live one
  only by case now fails with the same unique violation, on the same
  constraint name (`user_communication_methods_channel_code_key`), as an exact
  duplicate. This applies to every channel, not just email. Phone numbers are
  unaffected as long as you normalize them before storing.

  **Upgrading an existing database:** migrate with `@smplcty/schema-flow`
  0.21.1 or newer. It swaps in the new index without `--allow-destructive`
  and never leaves the table without one. Older versions skip the change
  unless you pass the flag, and can leave a broken index behind if it fails.

  The migration fails if two live contact methods already differ only by
  case. If it does, the old index stays in place and the error names the
  duplicated address. Resolve each pair (soft-delete or edit one of them)
  and run it again. To find them before upgrading:

  ```sql
  SELECT communication_channel_id, lower(code), count(*)
  FROM user_communication_methods
  WHERE deleted_at IS NULL
  GROUP BY 1, 2
  HAVING count(*) > 1;
  ```

  (#19)

## [9.0.1] - 2026-10-06

### Changed

- **Tenant-scoped tables can now be read in parallel under RLS.** The scope
  functions every policy calls are now `PARALLEL RESTRICTED` instead of
  `PARALLEL UNSAFE`, and the built-in `tenants` policy resolves the actor's
  tenants with `tenant_id = ANY (ARRAY(SELECT auth_tenant_ids()))`. Before this, a
  scan of any table under these policies ran on a single process. On a large
  tenant-scoped read the parallel plan took about a third of the time. To
  benefit in your own policies, write the tenant set the same way:
  `tenant_id IN (SELECT auth_tenant_ids())` still works and still sees the same
  rows, but it keeps the scan from running in parallel. (#17)
- **Node.js 22 or newer is now required.** Node.js 20 stopped receiving
  security updates in April 2026. `@smplcty/auth` is tested on Node.js 22 and 24.

## [9.0.0] - 2026-07-04

### Security

- **Pinned `search_path` on all seven `SECURITY DEFINER` functions**
  (`auth_has_role`, `auth_can_admin_user`, `auth_in_tenant`, `auth_all_tenants`,
  `auth_tenant_ids`, `resolve_session`, `auth_create_user`) to
  `pg_catalog, public`. These functions run with elevated (definer) rights and
  are called from RLS policies; without a pinned path they inherited the
  caller's `search_path`, letting a caller who plants a shadow object (a fake
  `user_roles` table, a fake `current_user_id()`) in an earlier-resolving schema
  redirect an unqualified name inside the function to their object and subvert an
  authorization decision. Pinning to the trusted schema list closes that vector.
  `current_user_id()` is `SECURITY INVOKER` and carries no escalation risk, so it
  is intentionally left unpinned.

### Changed

- **Now requires `@smplcty/schema-flow >= 0.18.2`** (was `>= 0.14.0`), for
  correct emission and drift-free convergence of the new `SECURITY DEFINER`
  `search_path` pins.

### Notes

- The pin hardcodes `public`, so **auth must be deployed into the `public`
  schema** while this holds — true for every consumer today. Deploying into a
  non-`public` schema is a known limitation (schema-flow can't yet interpolate
  the deploy schema into the pin); see the README's "Consuming with
  schema-flow" section.

## [8.1.0] - 2026-07-04

### Added

- **`auth_tenant_ids()` and `auth_all_tenants()`** — set-based, planner-friendly
  companions to `auth_in_tenant()` for tenant-scoped RLS on large tables.
  `auth_tenant_ids()` returns the tenant ids the current actor holds a role in;
  `auth_all_tenants()` is true when they hold a wildcard (all-tenants) role. Used
  together in a policy —
  `USING ((SELECT auth_all_tenants()) OR tenant_id IN (SELECT auth_tenant_ids()))`
  — the actor's reachable scope is resolved **once per query** instead of once
  per row, so tenant scope checks scale on big scans. `auth_in_tenant()` is
  unchanged and remains the right choice for scalar, one-off call sites.

### Changed

- **The built-in `tenants` visibility policy now uses the decorrelated scope
  form.** Behaviour is identical (a tenant is visible to any member; wildcard
  roles see all), but the scope is resolved once per query rather than per row.
  Consumers that apply tenant scope to large tables can adopt the same pattern
  with the new `auth_tenant_ids()` / `auth_all_tenants()` helpers.

## [8.0.0] - 2026-06-19

### Added

- **`user_communication_methods.qualifier`** — an optional, nullable free-text
  label on a contact method, for distinguishing two methods of the same channel
  (e.g. a "work" vs "home" phone). The value is consumer-defined; the library
  never interprets, requires, or populates it. Consumers that carried a ucm
  extend solely for this column can drop it.
- **`auth_create_user` accepts an optional `qualifier`** on each
  `communication_methods` entry and stores it verbatim (absent → `NULL`), so a
  consumer that wants to set a label no longer needs a follow-up `UPDATE`.

### Changed

- **`auth_create_user` now raises a friendly, catchable duplicate-contact
  error.** When a requested `(channel, code)` already belongs to a live
  communication method, the function raises `SQLSTATE 23505`
  (`unique_violation`) with a message naming the channel
  (`a user with this email already exists`) instead of letting a raw constraint
  violation escape. `23505` is raised _only_ for this case — every other failure
  carries the default `P0001` code — so a consumer can map a duplicate contact to
  a `4xx` ("that email/phone is already in use") without parsing constraint
  names.

### Security

- **`tenants.slug` now carries a DNS-label format CHECK**
  (`tenants_slug_format_check`). The slug _is_ the tenant sub-domain
  (`acme.app.com`), so it must be a valid DNS label — lowercase alphanumerics
  with internal hyphens, no leading/trailing hyphen. An invalid slug (an
  unroutable host) is now rejected at the database instead of relying on every
  consumer to re-declare the check. The constraint is NULL-safe, since slug is
  optional. Existing rows with a non-conforming slug must be corrected before
  migrating.

## [7.0.1] - 2026-06-19

### Changed

- Documented two previously-implicit sign-in contracts. The `@smplcty/auth/oidc`
  handler now spells out its trust boundary: `complete()` resolves the user by
  the verified `id_token` email **globally**, so an `auth_domains` IdP is trusted
  to assert only identities it is authoritative for — partition tenants by
  verified email domain. And `signInOptions().authDomains` now documents that the
  list **may mix `integrationType`s**; consumers must branch on `integrationType`
  and only start protocols they can drive (today only `oidc` has a shipped
  handler). Documentation only — no behavior change.

## [7.0.0] - 2026-06-19

### Changed

- **Migrating this schema now requires `@smplcty/schema-flow >= 0.14.0`.** The
  `resolve_session` function returns a `TABLE(… expires_at timestamptz …)`, and
  before `0.14.0` schema-flow compared that alias against Postgres's canonical
  `timestamp with time zone` and reported a phantom difference on every
  `plan`/`run`/`drift` — the function never converged to zero operations.
  `0.14.0` canonicalises function return, `TABLE(...)`, and argument types
  before comparing, so the auth schema now settles clean. Upgrading an existing
  database may need a one-time `--allow-destructive` run: `0.14.0` applies a
  changed function return type with `DROP … CASCADE` + a convergence pass that
  recreates the dependent RLS policies, and replaces any plain `UNIQUE`
  constraint that shares a name with one of auth's partial-unique indexes with
  the correct partial index.

## [6.0.0] - 2026-06-19

### Changed

- **(runtime): `withSession` now auto-selects a user's sole role.** When no
  `roleName` is requested, a user who holds exactly one role gets it as their
  active role — whether or not it is flagged default — so an admin who only
  holds `security` (or a settings-only admin) no longer needs to also be granted
  the default `user` role just to get an active role. Roles are counted by name,
  so the same role held across several tenants still counts as one. A user with
  two or more distinct roles (e.g. different roles in different tenants) is
  unchanged: it falls back to the default role, or none if there isn't one.

### Added

- **(schema): role-aware, tenant-scoped row-level security on the auth tables.**
  The library now ships RLS so a consuming app gets correct multi-tenant
  isolation out of the box — keyed entirely on its own `user_roles` and the
  standard `user` / `settings` / `security` roles, with no app-specific columns,
  so it never reaches into the business domain. The request role (`app_rls`) sees
  `tenants` it belongs to; a `settings` admin maintains `auth_domains` for tenants
  they administer and (with global access) creates tenants; a `security` admin
  manages the `users`, `user_roles`, and `user_communication_methods` of the
  tenants they administer, while a plain user sees only its own identity rows.
  `roles` and `communication_channels` stay public; `sessions` and
  `dev_otp_enrollments` are reached only through the privileged pool. The
  `app_privileged` pool and the `SECURITY DEFINER resolve_session` are unaffected.

- **(schema): `auth_create_user(jsonb)` — authority-checked, atomic user
  provisioning.** Creating a user, its communication methods, and its role
  assignments now happens in one call that refuses to leave a half-provisioned
  user behind (at least one access and one contact method are required) and
  enforces that the caller holds `security` over every tenant being granted — a
  tenant-scoped admin cannot create a global user or grant access to a tenant
  they do not administer. Raw `INSERT` on `users` is closed under RLS, so this is
  the app's path to provision a user; OIDC auto-provisioning still runs through
  the bypass pool.

- **(schema): the library now owns the grants on its own tables — tiered by
  trust.** Grants are declared explicitly per table (no blanket mixin) and target
  two roles the deployment provides: **`app_rls`**, the per-request, RLS-bound
  role, and **`app_privileged`**, the trusted `BYPASSRLS` auth machinery (a member
  of `app_rls`). `app_rls` gets only what a request needs — `SELECT` on reference
  data, `SELECT/INSERT/UPDATE` on the RLS-gated identity tables, `SELECT/UPDATE`
  on `users` — and **no** access to the credential tables (`sessions`,
  `dev_otp_enrollments`), no raw `users` INSERT, and no writes to reference data.
  `app_privileged` gets the privileged delta directly (credential CRUD + `users`
  INSERT for OIDC provisioning), which role membership does **not** leak back to
  `app_rls`. This both eliminates the per-app grant-only extends — the missing
  `dev_otp_enrollments` grant that silently broke OTP sign-in (the pre-send read
  hit `permission denied` while `/sign-in` still returned 200) belongs on the
  `app_privileged` machinery, not the request role — and closes the request role's
  direct access to credentials, secrets, reference data, and unauthorized
  provisioning. No `DELETE` (soft-delete everywhere); sequence `USAGE` is
  auto-derived from the `INSERT` grants. The library grants to the roles but does
  **not** declare them — the consuming app/infra owns role creation, credentials,
  and the `app_privileged` → `app_rls` membership; a `GRANT` against an absent
  role fails fast.

### Fixed

- **(schema): back-fill the standard role values on databases that already had
  the `roles` rows.** Seeds are insert-only, so a database that gained the
  `display_name` / `description` / `is_default` / `is_privilege` columns _after_
  its role rows already existed kept the column defaults — most importantly
  `is_default = false` on every role, which left `withSession` with no default
  role to select. A migration post-script now sets the canonical values on any
  never-seeded standard role (`user`, `settings`, `security`), guarded so it is
  a no-op on a fresh database and never touches a role a consumer has renamed or
  customised.

## [5.0.0] - 2026-06-16

### Added

- **(schema): ship the `email` and `phone` communication channels as seeds.**
  These are the two channels the library already resolves by name — the OIDC
  handler matches users on `email`, and the Twilio method router maps an
  identifier to `email` or `phone` — so a fresh database now has them out of
  the box instead of requiring the app to insert them. Matched by name with no
  pinned id and seeded insert-only, so re-runs are a no-op and consumers can
  add their own channels by name.

- **(schema): service user names are now unique.** A partial-unique index
  prevents two live service principals (`kind = 'service'`) from sharing a
  name. Service users are looked up by name (background workers, audit
  attribution), so a duplicate name made that lookup ambiguous. Human users
  are unaffected — real people legitimately share names and are referenced by
  id. The name frees up again once a service user is soft-deleted.

### Changed

- **(schema): seeding is now insert-only; requires `@smplcty/schema-flow >=
0.13.0`.** The shipped seeds (the `app-init` service user, the standard
  roles) no longer carry the `seeds_on_conflict` setting — `schema-flow`
  `0.13.0` makes "insert new rows, never overwrite existing ones" the default,
  which is exactly the behaviour those seeds always wanted. Re-running a
  migration stays a no-op, and a consumer's edits to the standard role rows
  are no longer at risk of being clobbered on the next migration. Migrating
  this schema now requires `@smplcty/schema-flow >= 0.13.0`.

## [4.0.0] - 2026-06-15

### Changed

- **(schema): seeded rows no longer pin literal ids.** The `app-init` service
  principal and the standard `user` / `settings` / `security` roles are now
  seeded without explicit primary keys — schema-flow matches them by their
  natural keys (`name` + `kind` for the user, `name` for the roles), so re-runs
  stay idempotent without a hard-coded id. The library already resolves these
  rows by name, never by id, so nothing functional changes; the previous
  "reserved ids 1–3, consumers use ≥ 100" convention for roles no longer
  applies — add your own roles by name. Existing databases are unaffected
  (their rows match by name and keep whatever ids they already have).
  **Migrating this schema now requires `@smplcty/schema-flow >= 0.12.0`**,
  which fully supports seeds with no primary keys.

### Added

- **(schema): audit attribution on `communication_channels` and
  `user_communication_methods`.** These long-lived tables previously tracked
  only soft-delete state; they now carry the full `audit` mixin (`created_at` /
  `updated_at` / `created_by` / `updated_by`), so you can see who added a
  contact channel or registered a user's communication method, and when —
  matching the attribution already on `users`, `tenants`, `roles`,
  `user_roles`, and `auth_domains`. Rows seeded during migration are
  back-filled to the `app-init` service principal by the existing audit
  back-fill post-script, so no new migration step is required.

### Removed

- **(schema): dropped the unused `label` column from `dev_otp_enrollments`.**
  It duplicated information already reachable through the foreign key
  (`user_communication_methods` → `users.name` + the method's `code`), and the
  library never read it — the authenticator-visible label is supplied directly
  to `getDevOtpEnrollmentUri`. `dev_otp_enrollments` stays soft-delete-only
  (un-audited, like `sessions`): every write to it is either creation or the
  actor-less usage counter bumped by `verifyDevOtp` during pre-auth
  verification, so there is no `updated_by` to attribute. Capture
  "who enrolled this secret" as an application-level audit-log event if you
  need it.

## [3.0.0] - 2026-06-14

### Changed

- **BREAKING (schema): identity columns are now `bigint` / `bigserial`.** All
  identity primary keys and the foreign keys that reference them — `users`,
  `tenants`, `roles`, `user_roles`, `auth_domains`, `communication_channels`,
  `user_communication_methods`, `sessions`, `dev_otp_enrollments` — widened from
  `serial`/`integer` to `bigserial`/`bigint`, and `current_user_id()` /
  `resolve_session()` now return `bigint`. This matches the already-`bigint`
  audit columns from `@smplcty/schema-std` and lets `bigint` apps consume the
  schema by reference without a type conflict (schema-flow's `extend:` can't
  change an imported column's type). The TypeScript API is unchanged — ids are
  still `number`; the library parses the `bigint` values pg returns as strings
  back to `number` at every boundary. **Fresh installs are unaffected; a
  database already created with the previous `int4` schema must widen its
  identity columns (schema-flow can't do `serial`→`bigserial` declaratively, so
  it needs a one-off pre-script).**

## [2.1.0] - 2026-06-14

### Added

- **`@smplcty/auth/http` — a framework-agnostic transport tier.** New opt-in
  subpath that wires the existing primitives (method router, OIDC handler,
  session lifecycle) into Web-standard `(Request) => Promise<Response>`
  handlers, so an app gets the full sign-in surface without hand-writing it:
  - `createAuthHandlers(config)` exposes `sign-in/options`, `otp/initiate`,
    `otp/complete`, `oidc/start`, `oidc/callback`, `sign-out`, and `session`,
    plus a `handle(request)` dispatcher (returns `null` for non-auth routes).
  - Cookie helpers and a short-lived **HMAC-signed** OIDC login-state cookie
    (state/nonce/codeVerifier) built on Web Crypto — edge-safe, no `Buffer`.
  - `getSessionToken` and `withRequestSession` for per-request auth middleware.
  - Same-origin `returnTo` enforcement (open-redirect guard) and server-side
    enforcement of `allow_otp`.
    Mounts directly in Hono (`app.all('/auth/*', (c) => handlers.handle(c.req.raw))`)
    or as Next.js App Router route handlers. Twilio and `oauth4webapi` stay
    optional peers — the app passes the handlers it constructed via config.

## [2.0.2] - 2026-06-13

### Added

- The documentation site now shows the released version as a badge in its
  header, linking to the matching GitHub release. The version is derived from
  the package version at build time, so it always reflects the current release.

## [2.0.1] - 2026-06-12

### Changed

- Maintenance: refreshed dependencies to their latest patch/minor releases.

## [2.0.0] - 2026-06-12

### Changed

- **OIDC now runs on [`oauth4webapi`](https://github.com/panva/oauth4webapi)**
  (ADR-0001). `@smplcty/auth/oidc`'s `oidcHandler` does the real flow —
  discovery + PKCE/state/nonce (`initiate` → `{ redirectUrl, loginState }`) and
  code→token exchange + `id_token` verification (`complete({ db, authDomain,
callbackUrl, loginState })`). The app persists `loginState` across the
  redirect; the `client_secret` is supplied via a `clientSecret` resolver from
  your secret store (not `auth_domains`). `oauth4webapi` replaces `@smplcty/oidc`
  as the optional peer for the `/oidc` subpath.
- **The method router is OTP-only.** `createMethodRouter` now exposes
  `signInOptions` (discovery) + `initiateOtp`/`completeOtp` (gated by
  `allow_otp`). OIDC is driven directly via `oidcHandler` (its `authorize`/
  `callback` shape is richer than the generic two-phase handler).

### Removed

- `@smplcty/oidc` dependency (deprecated; superseded by `oauth4webapi`).
- The router's generic `handlers` map and `initiate(authDomainId)` /
  `complete(authDomainId, credential)` dispatch, and `UnknownMethodError`
  (OIDC no longer routes through the generic interface).

## [1.0.0] - 2026-06-12

The v1 redesign (see `docs/v1-design.md`): one auth model shared by both apps —
stateful sessions, a pluggable sign-in method, an app-owned authorization scope,
and an identity contract the database reads per request. This is a major,
breaking change.

### Added

- **Privileges** — roles now carry an `is_privilege` flag. `is_privilege=false`
  roles are selectable modes/personas (drive the role switcher and the active
  role); `is_privilege=true` roles are always-on capability flags exported to
  the request. One `roles` table and one `user_roles` assignment cover both.
- **`withServiceContext(pool, serviceName, fn)`** — run background work as a
  named service principal so its writes are audited. Resolves the principal
  from a `users` row of `kind='service'` and sets `app.actor_id`.
- **Pluggable, tenant-centric sign-in methods** — a `MethodHandler` interface
  and a `createMethodRouter` that resolves sign-in by **sub-domain → tenant**:
  `signInOptions({ tenantSlug })` lists the tenant's IdPs (`auth_domains`, 1:N)
  and whether OTP is allowed; `initiate`/`complete` dispatch a chosen IdP by
  `integration_type`; `initiateOtp`/`completeOtp` run the user-bound OTP path,
  **gated by the tenant's `allow_otp`** (enforced in the router, so an SSO-only
  tenant can't be bypassed). One IdP → straight redirect; several → an app-rendered
  chooser. Opt-in handler subpaths `@smplcty/auth/oidc` (org-bound) and
  `@smplcty/auth/twilio` (user-bound); auth core pulls in neither `jose` nor
  Twilio.
- **Tenant sub-domain + SSO-only switch** — `tenants.slug` (the sub-domain the
  router resolves the tenant from, so OIDC needs no "which org?" form) and
  `tenants.allow_otp` (set false to enforce SSO-only). `auth_domains` is now
  1:N per tenant, resolved by `auth_domain_id`, with a `display_name` for the
  chooser button (the old globally-unique `code` is gone).
- **Pluggable authorization scope** — `withSession` accepts an app-supplied
  `scope` hook to set intra-tenant scope GUCs. A ready-made flat-tenant preset
  ships at `@smplcty/auth/flat-tenant` for the common case.
- **`revokeUserSessions(userId)`** and **`revokeTenantSessions(tenantId)`** —
  force sign-off for one user or a whole tenant. Tenant sign-off resolves
  membership from `user_roles.tenant_id` and deliberately spares wildcard
  (all-tenant) members.
- **`touchSession(token)`** — record activity (`last_seen_at`) on a live session.
- **Audit attribution** — auditable tables (`users`, `tenants`, `roles`,
  `user_roles`, `auth_domains`) carry the `audit` mixin, stamping
  `created_by`/`updated_by` from `app.actor_id`.
- **Soft delete** — every table carries the `soft_delete` mixin (`deleted_at`).
  Session resolution (`resolve_session`, `validateSession`),
  `findUserByCommunicationMethod`, `getUserRoleNames`, and the flat-tenant
  preset all treat soft-deleted rows as gone, so a soft-deleted session, user,
  communication method, or role assignment stops taking effect immediately.
  Unique indexes are partial (`WHERE deleted_at IS NULL`) so a name/code can be
  reused after its row is archived. The library honors `deleted_at` but ships
  no delete setter — clearing/setting it is a plain write the app owns.
- **`auth_domains`** table — per-tenant sign-in federation config, owned by auth.
- **`users.kind`** (`human` | `service`) and a seeded `app-init` service
  principal for background/bootstrap writes.

### Changed

- **Session tokens are hashed at rest.** `createSession` returns a raw opaque
  token once (`session.token`); only its SHA-256 hash is stored. `withSession`,
  `validateSession`, `revokeSession`, and `touchSession` now take the raw token.
- **Identity GUC contract** — the library sets exactly `app.actor_id`,
  `app.session_id`, `app.active_role`, and `app.privileges`. The old
  `app.role_name` / `app.tenant_ids` / `app.all_tenants` are gone from the core;
  tenant GUCs move to the flat-tenant preset.
- **Active-role selection moved into `withSession` (TypeScript).**
  `resolve_session` is now a pure resolver that validates nothing and takes no
  role argument; `withSession` picks the requested role, else the user's default
  role, else none (privilege-only is not an error).
- **Generic schema is consumed, not owned** — `audit`/`soft_delete`/`timestamps`
  come from `@smplcty/schema-std` (parameterized); the transaction primitive
  comes from `@smplcty/db`. `withTransaction` is re-exported from `@smplcty/db`.
- Primary-key naming standardized to `{singular}_id` across the schema.

### Removed

- The library's own `withTransaction` implementation (now `@smplcty/db`'s).
- `RoleNotAssignedError` (replaced by `RoleNotHeldError`), and the
  `Session.sessionId` field (replaced by `Session.token`).
- Baked-in tenant scope from `withSession` (now the flat-tenant preset).

## [0.6.4] - 2026-06-10

### Changed

- Maintenance release with no functional or API changes. Internal tooling now
  formats the codebase with Prettier (enforced on commit) and generates GitHub
  release notes from this changelog.

## [0.6.3] - 2026-04-12

Baseline release. Notes for this and earlier versions are on the
[GitHub releases page](https://github.com/mabulu-inc/simplicity-auth/releases);
the Keep a Changelog history starts from the next release.

[Unreleased]: https://github.com/mabulu-inc/simplicity-auth/compare/v9.0.1...HEAD
[9.0.1]: https://github.com/mabulu-inc/simplicity-auth/compare/v9.0.0...v9.0.1
[9.0.0]: https://github.com/mabulu-inc/simplicity-auth/compare/v8.1.0...v9.0.0
[8.1.0]: https://github.com/mabulu-inc/simplicity-auth/compare/v8.0.0...v8.1.0
[8.0.0]: https://github.com/mabulu-inc/simplicity-auth/compare/v7.0.1...v8.0.0
[7.0.1]: https://github.com/mabulu-inc/simplicity-auth/compare/v7.0.0...v7.0.1
[7.0.0]: https://github.com/mabulu-inc/simplicity-auth/compare/v6.0.0...v7.0.0
[6.0.0]: https://github.com/mabulu-inc/simplicity-auth/compare/v5.0.0...v6.0.0
[5.0.0]: https://github.com/mabulu-inc/simplicity-auth/compare/v4.0.0...v5.0.0
[4.0.0]: https://github.com/mabulu-inc/simplicity-auth/compare/v3.0.0...v4.0.0
[3.0.0]: https://github.com/mabulu-inc/simplicity-auth/compare/v2.1.0...v3.0.0
[2.1.0]: https://github.com/mabulu-inc/simplicity-auth/compare/v2.0.2...v2.1.0
[2.0.2]: https://github.com/mabulu-inc/simplicity-auth/compare/v2.0.1...v2.0.2
[2.0.1]: https://github.com/mabulu-inc/simplicity-auth/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/mabulu-inc/simplicity-auth/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/mabulu-inc/simplicity-auth/compare/v0.6.4...v1.0.0
[0.6.4]: https://github.com/mabulu-inc/simplicity-auth/compare/v0.6.3...v0.6.4
[0.6.3]: https://github.com/mabulu-inc/simplicity-auth/releases/tag/v0.6.3
