# FEDNICE landlord activation API

This separate Node service sends and checks one-time activation SMS codes. It uses Africa's Talking as the SMS adapter and the existing `fednice-rental-system` Firebase project through the Firebase Admin SDK. Firebase stays on Spark; this API does not create a Firebase project or use Cloud Functions.

## Required setup before activation can work

1. Create an Africa's Talking account and configure its SMS product. For development, use its sandbox; production SMS requires a production account and airtime. Keep the API key private.
2. Deploy this folder as a Node web service with a stable HTTPS URL. Do not put secrets in GitHub Pages or commit a service-account key. A free backend host may sleep or be unsuitable for production; choose an always-on service for real landlords.
3. Set these server environment variables in the host dashboard:
   - `FIREBASE_SERVICE_ACCOUNT_JSON`: service-account JSON for the existing Firebase project only. Restrict this credential and never commit it.
   - `OTP_SECRET`: a long random secret (at least 32 random bytes).
   - `CORS_ORIGIN`: the exact GitHub Pages origin, e.g. `https://OWNER.github.io` (comma-separated if needed).
   - `AT_USERNAME`: Africa's Talking application username.
   - `AT_API_KEY`: Africa's Talking API key.
   - `AT_SENDER_ID`: optional approved sender ID.
   - `PORT`: supplied by most hosts; defaults to 3000 locally.
4. Set `window.FEDNICE_API_BASE` in the root `api-config.js` to the deployed HTTPS API base URL.
5. Enable Email/Password in Firebase Authentication and add the GitHub Pages domain under Authorized domains.
6. Review `firestore.rules` before applying it to the existing Firebase project. It closes public browser access, so the legacy `admin.html` and `payment.html` screens that use the public `codes` collection will stop working under these rules. Migrate or remove those legacy flows first; do not paste the rules into Firebase blindly.

The API keeps OTP hashes, five-minute expiry, a one-minute resend delay, and a five-attempt limit in Firestore. It never stores the password. The activation ticket is short-lived and consumed atomically when creating the landlord profile. Trial dates are recorded as 90 days from account activation. The KSh 1,000 charge is not collected automatically by this code; payment integration is a separate step.

## Local run

Use Node.js 20 or newer, configure the environment variables above, then run `npm install` and `npm start` from this folder. Africa's Talking sandbox can test delivery without sending a real production SMS.
