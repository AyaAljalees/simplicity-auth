-- Test-only seed data. Applied AFTER the canonical schema migration
-- (which seeds the app-init service principal, the standard 'user',
-- 'settings', 'security' roles, and the 'email' / 'phone' communication
-- channels via the seeds: blocks in schema/tables/).
--
-- This file is NOT shipped with the published package — it lives under
-- tests/fixtures/ and is only loaded by the test helper.
--
-- No primary keys are assigned here: every row is identified by its natural
-- key (name / slug / code), and cross-table references are resolved with
-- subqueries on those keys. Tests look the resulting ids up the same way (see
-- the `ids` map in tests/helpers/test-db.ts), so nothing depends on a literal
-- id value or on insertion order.
--
-- The test personas:
--   Alice            — single tenant ('user' on acme)
--   Bob              — multi-tenant ('user' on acme and globex) + 'can_export' privilege
--   GlobalAdmin      — global ('settings' with NULL tenant_id)
--   NoRoles          — no user_roles rows at all
--   transform-worker — service principal (kind='service'), no session
--
-- This whole file runs with app.actor_id set to the app-init principal (the
-- test helper resolves it by name), so the audit triggers stamp
-- created_by/updated_by on every audited insert.

-- Tenants exercise the three sign-in shapes:
--   acme    — two OIDC IdPs → chooser
--   globex  — one OIDC IdP  → auto-redirect
--   initech — no IdP        → OTP only
INSERT INTO tenants (name, slug) VALUES
  ('acme', 'acme'),
  ('globex', 'globex'),
  ('initech', 'initech')
ON CONFLICT DO NOTHING;

-- communication_channels ('email', 'phone') are seeded by the canonical
-- migration, so they already exist here — no need to re-seed them.

-- A privilege (is_privilege=true) for exercising app.privileges export.
INSERT INTO roles (name, display_name, is_privilege) VALUES
  ('can_export', 'Can Export', true)
ON CONFLICT DO NOTHING;

INSERT INTO users (name, kind) VALUES
  ('Alice', 'human'),
  ('Bob', 'human'),
  ('GlobalAdmin', 'human'),
  ('NoRoles', 'human'),
  ('transform-worker', 'service')
ON CONFLICT DO NOTHING;

INSERT INTO user_communication_methods (user_id, communication_channel_id, code)
SELECT u.user_id, cc.communication_channel_id, v.code
FROM (VALUES
  ('Alice', 'email', 'alice@acme.com'),
  ('Bob', 'email', 'bob@globex.com'),
  ('GlobalAdmin', 'email', 'admin@system.com'),
  ('NoRoles', 'email', 'noroles@acme.com')
) AS v(user_name, channel_name, code)
JOIN users u ON u.name = v.user_name
JOIN communication_channels cc ON cc.name = v.channel_name
ON CONFLICT DO NOTHING;

INSERT INTO user_roles (user_id, role_id, tenant_id)
SELECT u.user_id, r.role_id, t.tenant_id
FROM (VALUES
  ('Alice', 'user', 'acme'),        -- Alice on acme
  ('Bob', 'user', 'acme'),          -- Bob on acme
  ('Bob', 'user', 'globex'),        -- Bob on globex
  ('Bob', 'can_export', 'acme'),    -- Bob's privilege
  ('GlobalAdmin', 'settings', NULL) -- GlobalAdmin, all tenants
) AS v(user_name, role_name, tenant_slug)
JOIN users u ON u.name = v.user_name
JOIN roles r ON r.name = v.role_name
LEFT JOIN tenants t ON t.slug = v.tenant_slug
ON CONFLICT DO NOTHING;

-- Org-bound sign-in federation. acme has two IdPs (chooser); globex has one
-- (auto-redirect); initech has none.
INSERT INTO auth_domains (tenant_id, display_name, integration_type, integration_params)
SELECT t.tenant_id, v.display_name, v.integration_type, v.integration_params::jsonb
FROM (VALUES
  ('acme', 'Microsoft', 'oidc',
     '{"issuer":"https://login.microsoftonline.com/acme","clientId":"acme-ms","authorizationEndpoint":"https://login.microsoftonline.com/acme/oauth2/v2.0/authorize","redirectUri":"https://acme.app.com/callback"}'),
  ('acme', 'Google', 'oidc',
     '{"issuer":"https://accounts.google.com","clientId":"acme-goog","authorizationEndpoint":"https://accounts.google.com/o/oauth2/v2/auth","redirectUri":"https://acme.app.com/callback"}'),
  ('globex', 'Okta', 'oidc',
     '{"issuer":"https://globex.okta.com","clientId":"globex-okta","authorizationEndpoint":"https://globex.okta.com/oauth2/v1/authorize","redirectUri":"https://globex.app.com/callback"}')
) AS v(tenant_slug, display_name, integration_type, integration_params)
JOIN tenants t ON t.slug = v.tenant_slug
ON CONFLICT DO NOTHING;

-- Note: dev OTP enrollments are created at test runtime by the dev-otp
-- test file's beforeAll hook (using generateDevOtpSecret), not seeded
-- here. This keeps TOTP secrets out of the source tree and avoids
-- false positives from secret scanners.
