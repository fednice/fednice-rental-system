# Landlord registration payments (Equity manual review)

For the current setup, landlords pay through Equity Paybill 247247. The payment is not verified automatically by Daraja. Fednice must check the receipt in the Equity account or statement before approving it.

1. `register.html` creates the landlord's Firebase Authentication account. The raw password is sent directly to Firebase and is never stored in browser session storage.
2. The authenticated registration details are saved privately by the backend in `landlordRegistrationIntents`; Firestore client rules deny access to that collection.
3. The landlord enters the payment page. It shows KSh 1,000 (configurable) and the Equity account number configured on the backend.
4. The landlord pastes the M-Pesa receipt and original message. The authenticated backend links the review request to their account; a pasted SMS is not proof of payment.
5. An authorized, email-verified reviewer opens `admin.html`, matches the receipt and exact amount against the Equity account/statement, then approves or rejects it.
6. On approval, a first-time account profile is created and an email-verification link is sent. The subscription lasts 90 days from the verified payment. Existing landlords submit renewal payments from `renewal.html`; approval extends the existing account by 90 days without changing the password or rental records.
7. Expired subscriptions cannot access landlord houses, tenants, or billing. The landlord can sign in and use `renewal.html` to restore access. Tenant payment and login functions remain available.

## Render environment variables

Keep credentials in Render's private Environment settings. Never put them in `api-config.js`, HTML, GitHub, or a chat message.

Required for the backend:

- `FIREBASE_SERVICE_ACCOUNT_JSON` — Firebase Admin service-account JSON.
- `OTP_SECRET` — long random secret used for server-side code hashing.
- `CORS_ORIGIN` — `https://fednice.github.io`.
- `AT_USERNAME` and `AT_API_KEY` — existing Africa's Talking settings used for optional tenant SMS.
- `EQUITY_ACCOUNT_NUMBER` — optional override for the account/reference number used under Equity Paybill 247247. Defaults to `0726387275`; confirm before changing it.
- `PAYMENT_REVIEWER_EMAILS` — comma-separated Firebase Authentication email addresses allowed to approve/reject pending landlord payment submissions. Reviewers must also verify their email. Use only trusted administrators.

Optional:

- `LANDLORD_REGISTRATION_AMOUNT` — defaults to `1000` KSh.

After changing backend code or environment variables, redeploy the Render service. Publish the updated frontend and Firestore rules. Firestore rules keep payment-review and landlord registration-intent records private to the trusted backend service account.

## Important limits of the current payment method

Equity Paybill 247247 accepts the payment, but the application does not receive a bank payment webhook under a normal personal account setup. The submitted SMS is not independently verified by the app. A trusted reviewer must compare the code and amount with the Equity account/statement before approval. Do not approve based only on the pasted message. Later, replace the manual review with an Equity/Jenga merchant integration or an eligible M-Pesa business shortcode and provider callbacks.
