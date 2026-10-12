# FEDNICE rental access API

This Node service supports landlord activation and tenant access codes. It uses the existing `fednice-rental-system` Firebase project through the Firebase Admin SDK. Firebase stays on Spark; tenant setup codes are shown in the landlord dashboard and can be shared privately without SMS charges.

## Required setup before activation can work

1. Create an Africa's Talking account and configure its SMS product only if landlord activation SMS is needed. For development, use its sandbox; production SMS requires a production account and airtime. Keep the API key private.
2. Deploy this folder as a Node web service with a stable HTTPS URL. Do not put secrets in GitHub Pages or commit a service-account key. A free backend host may sleep or be unsuitable for production; choose an always-on service for real landlords.
3. Set these server environment variables in the host dashboard:
   - `FIREBASE_SERVICE_ACCOUNT_JSON`: service-account JSON for the existing Firebase project only. Restrict this credential and never commit it.
   - `OTP_SECRET`: a long random secret (at least 32 random bytes).
   - `CORS_ORIGIN`: the exact GitHub Pages origin, e.g. `https://OWNER.github.io` (comma-separated if needed).
   - `AT_USERNAME`: Africa's Talking application username.
   - `AT_API_KEY`: Africa's Talking API key.
   - `AT_SENDER_ID`: optional approved sender ID.
   - `AT_PAYMENT_THANK_YOU`: optional; leave unset or set to `false` to keep payment thank-you SMS off. Set to `true` only when you are ready to use paid/live SMS. A message is requested after the landlord confirms a tenant's payment.
   - `PORT`: supplied by most hosts; defaults to 3000 locally.
4. Set `window.FEDNICE_API_BASE` in the root `api-config.js` to the deployed HTTPS API base URL.
5. Keep Firebase Authentication enabled and add the GitHub Pages domain under Authorized domains. Landlord sign-in stays email/password. Tenant phone/password credentials are verified by this API, which returns a short-lived Firebase custom token after successful sign-in.
6. Publish the root `firestore.rules` for the landlord portal. It allows each signed-in landlord to access only their own rental records and denies browser access to tenant access codes and password credential records. Tenant rental details are read through the authenticated API, which links each Firebase UID to exactly one tenant record. The former public `codes` generator/checkout has been retired; its existing Firestore documents are not deleted, but the browser cannot access them.

Landlord activation OTPs are hashed, expire after five minutes, and have resend and attempt limits. Tenant setup codes are eight characters, stored only as an HMAC, expire after seven days, and are consumed atomically once a tenant login is created. Tenant passwords are salted and hashed with scrypt; they are never stored in plaintext. Tenant sign-in allows five failed attempts before a 15-minute lock. The tenant phone must match the landlord's record, but this no-SMS flow does not verify who owns that phone number; the landlord should share the setup code privately with the intended tenant. M-Pesa confirmations pasted by a tenant are recorded as pending and must be checked against the landlord's M-Pesa statement before approval. Receipt codes are unique across submissions. The tenant dashboard displays an in-app thank-you after landlord confirmation. Optional thank-you SMS is disabled unless `AT_PAYMENT_THANK_YOU=true`; when enabled, the API sends the SMS request after confirmation and records whether the provider accepted or rejected the request. Provider acceptance is not a guarantee that the handset received the message, and live SMS may incur charges. Automatic WhatsApp messages are not configured. When a landlord deletes a vacated tenant, the API disables that tenant's Firebase account and removes the stored password hash. The KSh 1,000 charge is not collected automatically by this code; payment integration is a separate step.

## Local run

Use Node.js 20 or newer, configure the environment variables above, then run `npm install` and `npm start` from this folder. Africa's Talking sandbox can test delivery without sending a real production SMS.
