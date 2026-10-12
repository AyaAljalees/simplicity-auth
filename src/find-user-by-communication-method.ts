import { InvalidInputError } from './errors.js';
import type { FindUserQuery, Queryable, UserByCommunicationMethod } from './types.js';

const SELECT_BY_COMMUNICATION_METHOD = `
  SELECT
    ucm.user_id                       AS "userId",
    ucm.user_communication_method_id  AS "userCommunicationMethodId"
  FROM user_communication_methods ucm
  JOIN communication_channels cc
    ON cc.communication_channel_id = ucm.communication_channel_id
  JOIN users u ON u.user_id = ucm.user_id
  WHERE cc.name = $1
    AND lower(ucm.code) = lower($2)
    AND ucm.deleted_at IS NULL
    AND cc.deleted_at IS NULL
    AND u.deleted_at IS NULL
  LIMIT 1
`;

/**
 * Look up the user attached to a communication method (an email address,
 * phone number, etc). Returns `null` if no matching record exists.
 *
 * `code` matches in any casing (`Bob@Acme.com` finds `bob@acme.com`); the
 * stored code keeps the casing it was entered with. Normalize phone numbers
 * before storing and before calling this.
 *
 * Returning `null` instead of throwing is deliberate: the caller (a
 * sign-in endpoint, typically) decides whether to expose user-existence
 * information to the client. To avoid the user-enumeration oracle, most
 * sign-in endpoints should return the same response regardless of
 * whether this returns a value or `null`.
 *
 * @example
 * ```ts
 * const lookup = await findUserByCommunicationMethod(db, {
 *   channel: 'email',
 *   code: 'alice@example.com',
 * });
 * if (!lookup) {
 *   // user not registered — but return success anyway to avoid enumeration
 *   return { ok: true };
 * }
 * ```
 *
 * @throws {InvalidInputError} If `channel` or `code` is empty.
 */
export async function findUserByCommunicationMethod(
  db: Queryable,
  query: FindUserQuery,
): Promise<UserByCommunicationMethod | null> {
  if (typeof query?.channel !== 'string' || query.channel.length === 0) {
    throw new InvalidInputError('query.channel must be a non-empty string');
  }
  if (typeof query?.code !== 'string' || query.code.length === 0) {
    throw new InvalidInputError('query.code must be a non-empty string');
  }

  const { rows } = await db.query<UserByCommunicationMethod>(SELECT_BY_COMMUNICATION_METHOD, [
    query.channel,
    query.code,
  ]);
  const row = rows[0];
  if (!row) return null;
  // bigint ids arrive from pg as strings; the contract is `number`.
  return { userId: Number(row.userId), userCommunicationMethodId: Number(row.userCommunicationMethodId) };
}
