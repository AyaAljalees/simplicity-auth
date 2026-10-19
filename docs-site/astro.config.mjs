// @ts-check
import { readFileSync } from 'node:fs';
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// Single source of truth: the published version from the root package.json.
// Docs deploy on `release: published`, so the build-time version is always the
// released version — nothing to bump by hand.
const { version } = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
);

// https://astro.build/config
export default defineConfig({
  site: 'https://mabulu-inc.github.io',
  base: '/simplicity-auth',
  vite: {
    define: {
      __LIB_VERSION__: JSON.stringify(version),
    },
  },
  integrations: [
    starlight({
      title: '@smplcty/auth',
      components: {
        SiteTitle: './src/components/SiteTitle.astro',
      },
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/mabulu-inc/simplicity-auth',
        },
      ],
      sidebar: [
        {
          label: 'Getting started',
          items: [
            { label: 'Introduction', slug: 'getting-started/introduction' },
            { label: 'Installation', slug: 'getting-started/installation' },
            { label: 'Quick start', slug: 'getting-started/quick-start' },
          ],
        },
        {
          label: 'Sessions',
          items: [
            { label: 'withSession', slug: 'sessions/with-session' },
            { label: 'Authorization scope', slug: 'sessions/scope' },
            { label: 'Session lifecycle', slug: 'sessions/lifecycle' },
            { label: 'Background work', slug: 'sessions/background' },
          ],
        },
        {
          label: 'Sign-in methods',
          items: [
            { label: 'Overview', slug: 'methods/overview' },
            { label: 'OIDC', slug: 'methods/oidc' },
            { label: 'Email domains', slug: 'methods/email-domains' },
            { label: 'Developer OTP', slug: 'methods/dev-otp' },
          ],
        },
        {
          label: 'HTTP transport',
          items: [{ label: 'Drop-in handlers', slug: 'http/transport' }],
        },
        {
          label: 'Schema',
          items: [{ label: 'Required database schema', slug: 'schema/overview' }],
        },
        {
          label: 'Reference',
          items: [{ label: 'Identity GUC contract', slug: 'reference/identity-gucs' }],
        },
        {
          label: 'Security',
          items: [{ label: 'Security model', slug: 'security' }],
        },
        {
          label: 'Design',
          items: [
            { label: 'v1 design', slug: 'design/v1' },
            { label: 'ADR-0001 — OIDC', slug: 'design/adr-0001' },
          ],
        },
      ],
    }),
  ],
});
