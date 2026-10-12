import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { findUserByCommunicationMethod, InvalidInputError, withServiceContext } from '../src/index.js';
import { startTestDb, type TestDb } from './helpers/test-db.js';

describe('findUserByCommunicationMethod', () => {
  let db: TestDb;

  beforeAll(async () => {
    db = await startTestDb();
  });

  afterAll(async () => {
    await db.shutdown();
  });

  // user_communication_methods is audited, so writes need an actor in context.
  const insertEmail = (persona: 'Alice' | 'Bob', code: string) =>
    withServiceContext(db.pool, 'transform-worker', (client) =>
      client.query(
        `INSERT INTO user_communication_methods (user_id, communication_channel_id, code)
         SELECT u.user_id, cc.communication_channel_id, $2
         FROM users u, communication_channels cc
         WHERE u.name = $1 AND cc.name = 'email'`,
        [persona, code],
      ),
    );

  it('returns the user attached to a known email', async () => {
    const result = await findUserByCommunicationMethod(db.pool, {
      channel: 'email',
      code: 'alice@acme.com',
    });
    expect(result).toEqual({ userId: db.ids.users.alice, userCommunicationMethodId: db.ids.ucm.alice });
  });

  it('matches an email in any casing', async () => {
    for (const code of ['Alice@Acme.com', 'ALICE@ACME.COM']) {
      const result = await findUserByCommunicationMethod(db.pool, { channel: 'email', code });
      expect(result).toEqual({ userId: db.ids.users.alice, userCommunicationMethodId: db.ids.ucm.alice });
    }
  });

  it('keeps a code stored as entered and finds it in any casing', async () => {
    await insertEmail('Alice', 'Alice.Work@Acme.com');
    const { rows } = await db.pool.query<{ code: string }>(
      `SELECT code FROM user_communication_methods WHERE lower(code) = 'alice.work@acme.com'`,
    );
    expect(rows).toEqual([{ code: 'Alice.Work@Acme.com' }]);
    const result = await findUserByCommunicationMethod(db.pool, { channel: 'email', code: 'alice.work@acme.com' });
    expect(result?.userId).toBe(db.ids.users.alice);
  });

  it('rejects a live code that differs from another only by case, as an exact duplicate would', async () => {
    await expect(insertEmail('Bob', 'alice@acme.com')).rejects.toMatchObject({
      code: '23505',
      constraint: 'user_communication_methods_channel_code_key',
    });
    await expect(insertEmail('Bob', 'ALICE@acme.com')).rejects.toMatchObject({
      code: '23505',
      constraint: 'user_communication_methods_channel_code_key',
    });
  });

  it('looks up through the unique index', async () => {
    const client = await db.pool.connect();
    try {
      // The fixture tables are tiny; take seq scans off the table so the plan
      // shows whether the index is usable at all.
      await client.query('BEGIN');
      await client.query('SET LOCAL enable_seqscan = off');
      const { rows } = await client.query<{ 'QUERY PLAN': string }>(
        `EXPLAIN SELECT ucm.user_id
         FROM user_communication_methods ucm
         JOIN communication_channels cc ON cc.communication_channel_id = ucm.communication_channel_id
         WHERE cc.name = 'email' AND lower(ucm.code) = lower('Alice@Acme.com')
           AND ucm.deleted_at IS NULL AND cc.deleted_at IS NULL`,
      );
      await client.query('ROLLBACK');
      expect(rows.map((r) => r['QUERY PLAN']).join('\n')).toContain('user_communication_methods_channel_code_key');
    } finally {
      client.release();
    }
  });

  it('returns null for an unknown email', async () => {
    const result = await findUserByCommunicationMethod(db.pool, {
      channel: 'email',
      code: 'nope@nowhere.com',
    });
    expect(result).toBeNull();
  });

  it('returns null when channel does not match', async () => {
    // alice@acme.com exists as 'email', but not as 'phone'
    const result = await findUserByCommunicationMethod(db.pool, {
      channel: 'phone',
      code: 'alice@acme.com',
    });
    expect(result).toBeNull();
  });

  it('throws InvalidInputError on empty channel', async () => {
    await expect(findUserByCommunicationMethod(db.pool, { channel: '', code: 'x' })).rejects.toBeInstanceOf(
      InvalidInputError,
    );
  });

  it('throws InvalidInputError on empty code', async () => {
    await expect(findUserByCommunicationMethod(db.pool, { channel: 'email', code: '' })).rejects.toBeInstanceOf(
      InvalidInputError,
    );
  });

  it('parameterizes inputs and is immune to injection attempts', async () => {
    const result = await findUserByCommunicationMethod(db.pool, {
      channel: "email' OR 1=1; --",
      code: "anything' OR 1=1; --",
    });
    expect(result).toBeNull();
  });
});
