# Landlord payment-first registration

New landlord registration now follows this sequence:

1. `register.html` collects the profile and keeps the password temporarily in this browser tab's `sessionStorage`.
2. It redirects to `payment.html`, which displays the configured M-Pesa shortcode and fee (KSh 1,000 by default).
3. The landlord pastes the original M-Pesa message and receipt number. The server asks Safaricom Daraja Transaction Status to check it.
4. Only a completed transaction with the exact receipt and expected amount creates an active landlord profile. The active subscription lasts 90 days from payment.
5. Firebase Authentication sends an email-verification link. The new landlord cannot open the dashboard until that email is verified.

The pasted SMS is used to capture the receipt number and is not treated as proof. A live Daraja Transaction Status result is required.

## Render environment variables

Keep credentials in Render's private Environment settings. Never put them in `api-config.js`, HTML, GitHub, or a chat message.

Required for the current backend and new payment flow:

- `FIREBASE_SERVICE_ACCOUNT_JSON` — Firebase Admin service account JSON.
- `OTP_SECRET` — long random secret used for server-side code hashing.
- `CORS_ORIGIN` — `https://fednice.github.io`.
- `AT_USERNAME` and `AT_API_KEY` — existing Africa's Talking settings used for optional tenant SMS.
- `DARAJA_CONSUMER_KEY` and `DARAJA_CONSUMER_SECRET` — Daraja production app credentials.
- `DARAJA_SHORTCODE` — the FEDNICE Paybill or Till shortcode that receives the registration payments.
- `LANDLORD_PAYMENT_ACCOUNT_REFERENCE` — optional Paybill account/reference to show the payer; set only if your Paybill requires one.
- `DARAJA_INITIATOR` — Daraja API initiator username with Transaction Status query access.
- `DARAJA_SECURITY_CREDENTIAL` — Safaricom-encrypted API initiator credential (not the plaintext password).
- `DARAJA_CALLBACK_TOKEN` — a random private string of at least 32 characters.
- `PUBLIC_API_BASE` — `https://fednice-rental-system-2.onrender.com`.

Optional:

- `DARAJA_ENV` — `production` by default; set to `sandbox` only for simulator testing.
- `DARAJA_IDENTIFIER_TYPE` — defaults to `4` for an organization shortcode.
- `LANDLORD_REGISTRATION_AMOUNT` — defaults to `1000` KSh.

The Daraja API initiator must have the **Transaction Status query ORG API** role enabled for the shortcode. The `PUBLIC_API_BASE` callback URLs must be reachable over HTTPS. After setting these variables, deploy the backend on Render and publish the updated static pages on GitHub Pages. Firebase's email verification template and authorized domain settings remain managed in Firebase Authentication.

If the Daraja status callback cannot confirm the receipt, registration stays incomplete; do not activate the landlord manually from the pasted SMS alone.
