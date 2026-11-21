---
title: Emailed codes
description: Sign in with a code you email through your own provider, such as Amazon SES.
---

`emailCodeHandler` (`@smplcty/auth/email-code`) signs users in with a code you
email them. The library issues, stores and checks the code; you deliver it with
`sendCode`, through Amazon SES or any other provider, so auth depends on no mail
provider. It is the alternative to Twilio Verify's email channel, which works
only through SendGrid.

```ts
import { emailCodeHandler } from '@smplcty/auth/email-code';

const otpHandler = emailCodeHandler({
  codeSecret: process.env.EMAIL_CODE_SECRET, // at least 32 bytes, never in the database
  sendCode: ({ to, code }) => sendSignInEmail(to, code), // your message, your provider
});
```

What it enforces, which Twilio Verify would otherwise do for you:

- A code is six random digits and is valid for **10 minutes**.
- A code works **once**, and dies after **5 wrong guesses**, even if the next one is right.
- Sending a new code **retires the previous one** for good.
- At most **5 codes per address per 10 minutes**. A request over the limit sends nothing and the last code stays valid.
- Only an **HMAC** of each code is stored (`email_sign_in_codes`), keyed by `codeSecret`, so a database read alone can't brute-force the million possible codes. Rows are kept after use, expiry or replacement.
- Like the Twilio handler, it never provisions, reports `otpSent` for an unknown address without sending, and accepts a [dev-OTP](/simplicity-auth/methods/dev-otp/) code first, sending nothing to an enrolled user.
- If `sendCode` throws, the person keeps the code they already had, and the failed send doesn't count toward the limit. The code that never went out is kept as a record (`delivery_failed_at`) and can't be used.
- What the caller is told depends on what `sendCode` throws. Throw `DeliveryUnavailableError` when the provider can't send to anyone (it's down, or its credentials are wrong): everyone gets an honest "try again shortly" for a minute. Anything else, such as a rejected address, is answered as for an unknown address and logged without it. See [When a code can't be sent](/simplicity-auth/methods/overview/#when-a-code-cant-be-sent). Don't throw any other `AuthError` from `sendCode`: it reaches the caller, and since `sendCode` runs only for an address with an account, it would reveal that the address has one.

To send email codes yourself and SMS through Twilio, give `otpHandler` one
handler per kind of identifier. One containing `@` is an email; anything else is
a phone:

```ts
const otpHandler = {
  email: emailCodeHandler({ codeSecret, sendCode }),
  phone: twilioVerifyHandler({ client }),
};
```

The router picks the handler and keeps every check for both, including sending
no code to someone who must sign in with SSO. Prefer this to writing your own
dispatcher: one that doesn't forward `resolveUser` silently loses that check. A
kind you leave out isn't offered; a sign-in with it gets `OtpNotAllowedError`.
