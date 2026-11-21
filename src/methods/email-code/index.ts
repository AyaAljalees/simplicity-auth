import { createHmac, randomInt, timingSafeEqual } from 'node:crypto';
import { InvalidInputError } from '../../errors.js';
import { findUserByCommunicationMethod } from '../../find-user-by-communication-method.js';
import { isDevOtpEnrolled, verifyDevOtp } from '../../dev-otp.js';
import { VerificationFailedError } from '../errors.js';
import type { Queryable } from '../../types.js';
import type {
  MethodCompleteContext,
  MethodHandler,
  MethodInitiateContext,
  MethodInitiateResult,
  ResolvedUser,
} from '../types.js';

/** How long an emailed code stays valid. */
export const EMAIL_CODE_TTL_MINUTES = 10;
/** Wrong guesses a code survives; the next guess fails even if it is right. */
export const EMAIL_CODE_MAX_FAILED_ATTEMPTS = 5;
/** Codes sent to one address per {@link EMAIL_CODE_TTL_MINUTES}; further requests send nothing. */
export const EMAIL_CODE_MAX_SENDS = 5;

const MIN_SECRET_BYTES = 32;

/** The message the app delivers: the address and the code to put in it. */
export interface EmailCode {
  to: string;
  code: string;
}

export interface EmailCodeHandlerOptions {
  /** Keys the stored code hashes. At least 32 bytes, kept out of the database. */
  codeSecret: string | Buffer;
  /** Delivers the code, e.g. through Amazon SES. The app owns the message. */
  sendCode: (message: EmailCode) => Promise<void>;
}

// Issues a code only while the address is under the send limit, retiring the
// previous live code in the same statement so a refused send keeps it alive.
// Returns the new code's id and the ids it retired, so a failed delivery can
// be undone with UNDO_ISSUE.
const ISSUE_CODE = `
  WITH allowed AS (
    SELECT count(*) < $4 AS ok
    FROM email_sign_in_codes
    WHERE user_communication_method_id = $1
      AND created_at > now() - make_interval(mins => $3)
      AND delivery_failed_at IS NULL
  ),
  superseded AS (
    UPDATE email_sign_in_codes
    SET superseded_at = now()
    WHERE user_communication_method_id = $1
      AND used_at IS NULL
      AND superseded_at IS NULL
      AND (SELECT ok FROM allowed)
    RETURNING email_sign_in_code_id
  )
  INSERT INTO email_sign_in_codes (user_communication_method_id, code_hash, expires_at)
  SELECT $1, $2, now() + make_interval(mins => $3)
  WHERE (SELECT ok FROM allowed)
  RETURNING
    email_sign_in_code_id AS "id",
    (SELECT coalesce(array_agg(email_sign_in_code_id), '{}') FROM superseded) AS "retiredIds"
`;

// Undoes ISSUE_CODE after a failed delivery: the code nobody received is
// marked dead and stops counting toward the send limit (the row stays, as the
// record of the attempt), and the codes it retired are live again.
const UNDO_ISSUE = `
  UPDATE email_sign_in_codes
  SET
    delivery_failed_at = CASE WHEN email_sign_in_code_id = $1 THEN now() ELSE delivery_failed_at END,
    superseded_at = CASE WHEN email_sign_in_code_id = $1 THEN now() ELSE NULL END
  WHERE email_sign_in_code_id = $1
     OR email_sign_in_code_id = ANY($2::bigint[])
`;

const LIVE_CODE = `
  WHERE user_communication_method_id = $1
    AND used_at IS NULL
    AND superseded_at IS NULL
    AND expires_at > now()
    AND failed_attempts < $2
`;

const SELECT_LIVE_CODE = `
  SELECT email_sign_in_code_id AS "id", code_hash AS "codeHash"
  FROM email_sign_in_codes
  ${LIVE_CODE}
  ORDER BY created_at DESC
  LIMIT 1
`;

// Re-checks liveness so two concurrent correct guesses cannot both use the code.
const USE_CODE = `
  UPDATE email_sign_in_codes
  SET used_at = now()
  ${LIVE_CODE}
    AND email_sign_in_code_id = $3
  RETURNING email_sign_in_code_id
`;

const RECORD_FAILED_ATTEMPT = `
  UPDATE email_sign_in_codes
  SET failed_attempts = failed_attempts + 1
  WHERE email_sign_in_code_id = $1
`;

function requireIdentifier(identifier: string | undefined): string {
  if (typeof identifier !== 'string' || identifier.length === 0) {
    throw new InvalidInputError('the email code handler requires a non-empty identifier');
  }
  return identifier;
}

async function findUser(db: Queryable, identifier: string) {
  return findUserByCommunicationMethod(db, { channel: 'email', code: identifier });
}

/**
 * The user-bound emailed-code method handler (subpath `@smplcty/auth/email-code`).
 * The library issues, stores and checks the code; the app delivers it through
 * `sendCode`, so auth depends on no mail provider.
 *
 * A code is six random digits, valid for {@link EMAIL_CODE_TTL_MINUTES} minutes,
 * single-use, and dead after {@link EMAIL_CODE_MAX_FAILED_ATTEMPTS} wrong guesses.
 * Sending a new code retires the previous one. At most
 * {@link EMAIL_CODE_MAX_SENDS} are sent to an address per
 * {@link EMAIL_CODE_TTL_MINUTES} minutes. Only an HMAC of each code is stored,
 * in `email_sign_in_codes`, and rows are never deleted.
 *
 * Like the Twilio handler it never provisions, reports `otpSent` for an unknown
 * address or a refused send without sending, and accepts a dev-OTP code first.
 *
 * ```ts
 * import { emailCodeHandler } from '@smplcty/auth/email-code';
 *
 * const handler = emailCodeHandler({
 *   codeSecret: process.env.EMAIL_CODE_SECRET!,
 *   sendCode: ({ to, code }) => sendSignInEmail(to, code),
 * });
 * ```
 */
export function emailCodeHandler(options: EmailCodeHandlerOptions): MethodHandler {
  const { codeSecret, sendCode } = options;
  if (Buffer.byteLength(codeSecret) < MIN_SECRET_BYTES) {
    throw new InvalidInputError(`codeSecret must be at least ${MIN_SECRET_BYTES} bytes`);
  }

  const hashCode = (userCommunicationMethodId: number, code: string): Buffer =>
    createHmac('sha256', codeSecret).update(`${userCommunicationMethodId}:${code}`).digest();

  return {
    async resolveUser(ctx: MethodInitiateContext): Promise<ResolvedUser | null> {
      return findUser(ctx.db, requireIdentifier(ctx.identifier));
    },

    async initiate(ctx: MethodInitiateContext): Promise<MethodInitiateResult> {
      const identifier = requireIdentifier(ctx.identifier);
      const user = await findUser(ctx.db, identifier);
      if (!user || (await isDevOtpEnrolled(ctx.db, user.userCommunicationMethodId))) {
        return { otpSent: true };
      }

      const code = String(randomInt(0, 1_000_000)).padStart(6, '0');
      const { rows } = await ctx.db.query<{ id: string; retiredIds: string[] }>(ISSUE_CODE, [
        user.userCommunicationMethodId,
        hashCode(user.userCommunicationMethodId, code).toString('hex'),
        EMAIL_CODE_TTL_MINUTES,
        EMAIL_CODE_MAX_SENDS,
      ]);
      const issued = rows[0];
      if (issued) {
        try {
          await sendCode({ to: identifier, code });
        } catch (err) {
          // The person never got this code, so they keep the one they had.
          await ctx.db.query(UNDO_ISSUE, [issued.id, issued.retiredIds]);
          throw err;
        }
      }
      return { otpSent: true };
    },

    async complete(ctx: MethodCompleteContext): Promise<ResolvedUser> {
      const identifier = requireIdentifier(ctx.identifier);
      const user = await findUser(ctx.db, identifier);
      if (!user) {
        throw new VerificationFailedError();
      }
      const ucmId = user.userCommunicationMethodId;
      if (await verifyDevOtp(ctx.db, ucmId, ctx.credential)) {
        return user;
      }

      const { rows } = await ctx.db.query<{ id: string; codeHash: string }>(SELECT_LIVE_CODE, [
        ucmId,
        EMAIL_CODE_MAX_FAILED_ATTEMPTS,
      ]);
      const live = rows[0];
      if (!live) {
        throw new VerificationFailedError();
      }
      if (!timingSafeEqual(Buffer.from(live.codeHash, 'hex'), hashCode(ucmId, ctx.credential))) {
        await ctx.db.query(RECORD_FAILED_ATTEMPT, [live.id]);
        throw new VerificationFailedError();
      }
      const { rowCount } = await ctx.db.query(USE_CODE, [ucmId, EMAIL_CODE_MAX_FAILED_ATTEMPTS, live.id]);
      if (!rowCount) {
        throw new VerificationFailedError();
      }
      return user;
    },
  };
}
