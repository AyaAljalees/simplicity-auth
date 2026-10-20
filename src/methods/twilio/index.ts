import type { TwilioVerifyClient, VerificationChannel } from '@smplcty/twilio';
import { InvalidInputError } from '../../errors.js';
import { findUserByCommunicationMethod } from '../../find-user-by-communication-method.js';
import { verifyDevOtp, isDevOtpEnrolled } from '../../dev-otp.js';
import { VerificationFailedError } from '../errors.js';
import type {
  MethodCompleteContext,
  MethodHandler,
  MethodInitiateContext,
  MethodInitiateResult,
  ResolvedUser,
} from '../types.js';

/**
 * How an identifier maps onto a communication channel.
 *
 * - `channelName`   — the `communication_channels.name` to match the user
 *   on (e.g. 'email' / 'phone').
 * - `verifyChannel` — the Twilio Verify delivery channel ('sms' / 'email').
 */
export interface ResolvedChannel {
  channelName: string;
  verifyChannel: VerificationChannel;
}

export interface TwilioVerifyHandlerOptions {
  /** A Twilio Verify client from `createTwilioVerifyClient` (in the app). */
  client: TwilioVerifyClient;
  /** Map an identifier to its channel. Default: contains '@' → email,
   *  otherwise phone/sms. */
  resolveChannel?: (identifier: string) => ResolvedChannel;
}

function defaultResolveChannel(identifier: string): ResolvedChannel {
  return identifier.includes('@')
    ? { channelName: 'email', verifyChannel: 'email' }
    : { channelName: 'phone', verifyChannel: 'sms' };
}

// User-bound: the identifier (phone/email) is required. The router always
// supplies it via initiateOtp/completeOtp; this guards direct handler use.
function requireIdentifier(identifier: string | undefined): string {
  if (typeof identifier !== 'string' || identifier.length === 0) {
    throw new InvalidInputError('the Twilio handler requires a non-empty identifier');
  }
  return identifier;
}

/**
 * The user-bound Twilio Verify method handler (opt-in subpath
 * `@smplcty/auth/twilio`). Phase 1 sends an OTP (skipping the send for
 * dev-OTP-enrolled users); phase 2 verifies the submitted code — dev-OTP
 * first, then Twilio — and resolves the existing user.
 *
 * User-bound: it never provisions. The user must already have a
 * `user_communication_methods` row for the identifier. To avoid a
 * user-enumeration oracle, `initiate` reports `otpSent` even for an unknown
 * identifier (it just doesn't send); `complete` fails verification.
 *
 * Drives `@smplcty/twilio` (an **optional peer**); auth core depends on
 * neither it nor `jose`. Install the peer and pass a client:
 *
 * ```ts
 * import { createTwilioVerifyClient } from '@smplcty/twilio';
 * import { twilioVerifyHandler } from '@smplcty/auth/twilio';
 *
 * const handler = twilioVerifyHandler({ client: createTwilioVerifyClient(cfg) });
 * const router = createMethodRouter({ db: pool, handlers: {}, defaultHandler: handler });
 * ```
 */
export function twilioVerifyHandler(options: TwilioVerifyHandlerOptions): MethodHandler {
  const { client } = options;
  const resolveChannel = options.resolveChannel ?? defaultResolveChannel;

  return {
    async resolveUser(ctx: MethodInitiateContext): Promise<ResolvedUser | null> {
      const identifier = requireIdentifier(ctx.identifier);
      const { channelName } = resolveChannel(identifier);
      return findUserByCommunicationMethod(ctx.db, { channel: channelName, code: identifier });
    },

    async initiate(ctx: MethodInitiateContext): Promise<MethodInitiateResult> {
      const identifier = requireIdentifier(ctx.identifier);
      const { channelName, verifyChannel } = resolveChannel(identifier);
      const user = await findUserByCommunicationMethod(ctx.db, { channel: channelName, code: identifier });

      // Unknown identifier: report sent without sending (anti-enumeration).
      if (!user) {
        return { otpSent: true };
      }

      // Dev-OTP-enrolled devs generate their code from an authenticator
      // app, so skip the (likely undeliverable) SMS.
      if (await isDevOtpEnrolled(ctx.db, user.userCommunicationMethodId)) {
        return { otpSent: true };
      }

      await client.sendVerificationCode({ channel: verifyChannel, to: identifier });
      return { otpSent: true };
    },

    async complete(ctx: MethodCompleteContext): Promise<ResolvedUser> {
      const identifier = requireIdentifier(ctx.identifier);
      const { channelName } = resolveChannel(identifier);
      const user = await findUserByCommunicationMethod(ctx.db, { channel: channelName, code: identifier });
      if (!user) {
        throw new VerificationFailedError();
      }

      // Dev-OTP first (authenticator-app code), then Twilio Verify.
      const okDev = await verifyDevOtp(ctx.db, user.userCommunicationMethodId, ctx.credential);
      const ok = okDev || (await client.verifyVerificationCode({ to: identifier, code: ctx.credential }));
      if (!ok) {
        throw new VerificationFailedError();
      }

      return user;
    },
  };
}
