# FEDNICE Rental System

Static client pages hosted on GitHub Pages. Firebase Authentication and Firestore rules protect admin actions, one-time code redemption, and house records.

## Firebase setup

1. In Firebase Authentication, enable **Email/Password** and **Anonymous** sign-in. The admin page accepts only `fednicesolutions@gmail.com`.
2. In Firestore Database → Rules, publish the rules from [`firestore.rules`](firestore.rules). The deny-all rule is the safe temporary setting until these rules are published.
3. Keep the project on Spark if desired. This setup uses Firebase client SDKs and Firestore rules; it does not use Cloud Functions.
4. Publish the repository through GitHub Pages over HTTPS.

## Admin and data

- Open `/admin.html` and sign in as the FEDNICE administrator to create codes and import house records.
- Import CSV files with the headers `HouseNo,MonthlyRent,TenantName,Status`. Import them directly from the administrator page; do not commit tenant names, phone numbers, payment records, or identity information to this public repository.
- A code is six characters and burns once. Client access expires after one hour. The access document is removed after redemption while code history remains visible to the administrator.
- Collected rent is not displayed because this repository has no payment records or payment reconciliation integration.

## Important security limits

Firestore rules validate and restrict client operations, but a browser application cannot make a six-character code impossible to guess or provide server-side rate limiting. Enable Firebase App Check for the web app and Firestore after configuring its reCAPTCHA provider. Use stronger codes if this dashboard will hold sensitive tenant records.

`firebase.js` contains the Firebase web configuration. Firebase web API keys identify the project; Firestore security rules and App Check protect data access. Never commit service-account credentials or other private server keys.
