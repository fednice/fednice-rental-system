# Landlord registration payments (Equity manual review)

For the current setup, landlords pay through Equity Paybill 247247. The payment is not verified automatically by Daraja. Fednice must check the receipt in the Equity account or statement before approving it.

1. `register.html` collects the profile and keeps the password temporarily in this browser tab's `sessionStorage`.
2. It redirects to `payment.html`. The page shows KSh 1,000 (configurable) and the Equity account number configured on the backend.
3. The landlord pastes the M-Pesa receipt and original message. The backend stores a pending review request; this submission is not proof of payment.
4. An authorized reviewer opens `admin.html`, signs in, matches the receipt and exact amount against the Equity account/statement, then approves or rejects it.
5. If approved, the waiting registration continues, creates the Firebase account/profile, and sends an email-verification link. The subscription lasts 90 days from the verified payment.

## Render environment variables

Keep credentials in Render's private Environment settings. Never put them in `api-config.js`, HTML, GitHub, or a chat message.

Required for the backend:

- `FIREBASE_SERVICE_ACCOUNT_JSON` — Firebase Admin service-account JSON.
- `OTP_SECRET` — long random secret used for server-side code hashing.
- `CORS_ORIGIN` — `https://fednice.github.io`.
- `AT_USERNAME` and `AT_API_KEY` — existing Africa's Talking settings used for optional tenant SMS.
- `EQUITY_ACCOUNT_NUMBER` — optional override for the account/reference number used under Equity Paybill 247247. Defaults to `0726387275`; confirm before changing it.
- `PAYMENT_REVIEWER_EMAILS` — comma-separated Firebase Authentication email addresses allowed to approve/reject pending landlord payment submissions. Use only trusted administrators.

Optional:

- `LANDLORD_REGISTRATION_AMOUNT` — defaults to `1000` KSh.

After changing backend code or environment variables, redeploy the Render service. Publish the updated `payment.html` and `admin.html` through GitHub Pages. Firestore rules keep payment-review records private to the trusted backend service account.

## Important limits of the current payment method

Equity Paybill 247247 accepts the payment, but the application does not receive a bank payment webhook under a normal personal account setup. The submitted SMS is not independently verified by the app. A trusted reviewer must compare the code and amount with the Equity account/statement before approval. Do not approve based only on the pasted message. Later, replace the manual review with an Equity/Jenga merchant integration or an eligible M-Pesa business shortcode and provider callbacks.
