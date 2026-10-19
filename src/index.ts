// Errors
export {
  AuthError,
  SessionNotFoundError,
  SessionExpiredError,
  RoleNotHeldError,
  ServicePrincipalNotFoundError,
  InvalidInputError,
} from './errors.js';

// Types
export type {
  Queryable,
  Session,
  SessionInfo,
  SessionContext,
  SessionIdentity,
  ScopeHook,
  SessionAuth,
  CreateSessionInput,
  GeoLocation,
  UserByCommunicationMethod,
  FindUserQuery,
  Logger,
  WithSessionOptions,
} from './types.js';

// Session lifecycle
export { createSession } from './create-session.js';
export { validateSession } from './validate-session.js';
export { revokeSession, revokeUserSessions, revokeTenantSessions } from './revoke-session.js';
export { touchSession } from './touch-session.js';
export { findUserByCommunicationMethod } from './find-user-by-communication-method.js';
export { getUserRoleNames } from './get-user-role-names.js';

// Request bootstrapping
export { withSession } from './with-session.js';
// Background service context — for workers/Lambdas with no user session.
export { withServiceContext } from './with-service-context.js';

// The transaction primitive now lives in @smplcty/db; re-exported for
// convenience so consumers don't need a direct import for the common case.
export { withTransaction } from '@smplcty/db';

// Identity GUC helpers — must be called inside an open transaction.
export {
  IDENTITY_GUC,
  setLocal,
  setActorId,
  setSessionId,
  setActiveRole,
  setPrivileges,
  setIdentityContext,
} from './set-helpers.js';

// Authentication methods — pluggable two-phase handlers + auth_domains router.
export { createMethodRouter } from './methods/router.js';
export {
  EmailDomainNotVerifiedError,
  OtpNotAllowedError,
  SsoRequiredError,
  VerificationFailedError,
} from './methods/errors.js';
export type {
  MethodHandler,
  MethodInitiateResult,
  MethodInitiateContext,
  MethodCompleteContext,
  ResolvedUser,
  MethodRouter,
  MethodRouterOptions,
  SignInOptions,
  AuthDomain,
} from './methods/types.js';

// Developer OTP — for devs whose phones can't receive Twilio SMS.
export { verifyDevOtp, isDevOtpEnrolled, generateDevOtpSecret, getDevOtpEnrollmentUri } from './dev-otp.js';
