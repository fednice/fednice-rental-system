const crypto = require('node:crypto');
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const AfricaTalking = require('africastalking');

const required = ['FIREBASE_SERVICE_ACCOUNT_JSON', 'OTP_SECRET', 'CORS_ORIGIN', 'AT_USERNAME', 'AT_API_KEY'];
for (const key of required) if (!process.env[key]) throw new Error(`Missing required environment variable: ${key}`);

admin.initializeApp({ credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON)) });
const db = admin.firestore();
const at = AfricaTalking({ username: process.env.AT_USERNAME, apiKey: process.env.AT_API_KEY });
const sms = at.SMS;
const app = express();
app.disable('x-powered-by');
// Render terminates HTTPS at its proxy. Trust one proxy hop so req.ip is the client address.
app.set('trust proxy', 1);
app.use(cors({ origin: process.env.CORS_ORIGIN.split(',').map(value => value.trim()), methods: ['GET', 'POST'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.use(express.json({ limit: '16kb' }));

app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
  });
  if (req.secure || req.get('x-forwarded-proto') === 'https') {
    res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

// Lightweight per-IP limits for public endpoints. Use a shared store if scaling to
// multiple server instances; Firebase and per-account limits remain in place.
const rateBuckets = new Map();
function rateLimit({ windowMs, max, message }) {
  return (req, res, next) => {
    const now = Date.now();
    const key = `${req.ip}:${req.path}`;
    let bucket = rateBuckets.get(key);
    if (!bucket || bucket.resetAt <= now) bucket = { count: 0, resetAt: now + windowMs };
    bucket.count += 1;
    rateBuckets.set(key, bucket);
    if (rateBuckets.size > 10000) {
      for (const [bucketKey, value] of rateBuckets) if (value.resetAt <= now) rateBuckets.delete(bucketKey);
    }
    res.set('RateLimit-Limit', String(max));
    res.set('RateLimit-Remaining', String(Math.max(0, max - bucket.count)));
    res.set('RateLimit-Reset', String(Math.ceil((bucket.resetAt - now) / 1000)));
    if (bucket.count > max) return res.status(429).json({ error: message });
    next();
  };
}
const tenantRegisterLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 15, message: 'Too many registration attempts. Please wait and try again.' });
const tenantLoginLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, message: 'Too many login attempts. Please wait and try again.' });

const hash = value => crypto.createHmac('sha256', process.env.OTP_SECRET).update(value).digest('hex');
const phoneKey = phone => crypto.createHash('sha256').update(phone).digest('hex');
const tenantCodeAlphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function makeTenantCode() {
  return Array.from({ length: 8 }, () => tenantCodeAlphabet[crypto.randomInt(tenantCodeAlphabet.length)]).join('');
}
function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 32 * 1024 * 1024 });
}
function normalizePhone(value) {
  const digits = String(value || '').replace(/[\s()-]/g, '');
  if (/^07\d{8}$/.test(digits)) return `+254${digits.slice(1)}`;
  if (/^01\d{8}$/.test(digits)) return `+254${digits.slice(1)}`;
  if (/^254[17]\d{8}$/.test(digits)) return `+${digits}`;
  if (/^\+254[17]\d{8}$/.test(digits)) return digits;
  throw new Error('Enter a valid Kenyan mobile number, for example 0712345678.');
}
function asyncRoute(handler) { return (req, res, next) => Promise.resolve(handler(req, res)).catch(next); }
function requireAuth(req, res, next) {
  const match = String(req.headers.authorization || '').match(/^Bearer (.+)$/);
  if (!match) return res.status(401).json({ error: 'Please sign in again.' });
  admin.auth().verifyIdToken(match[1], true).then(decoded => { req.user = decoded; next(); }).catch(() => res.status(401).json({ error: 'Please sign in again.' }));
}

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.post('/api/tenant-access-codes', requireAuth, asyncRoute(async (req, res) => {
  const landlordRef = db.collection('landlords').doc(req.user.uid);
  const landlord = await landlordRef.get();
  if (!landlord.exists) return res.status(403).json({ error: 'An active landlord account is required.' });
  const tenantId = String(req.body.tenantId || '').trim();
  if (!/^[A-Za-z0-9_-]{1,150}$/.test(tenantId)) return res.status(400).json({ error: 'Choose a valid tenant record.' });
  const tenantRef = landlordRef.collection('tenants').doc(tenantId);
  const tenant = await tenantRef.get();
  if (!tenant.exists) return res.status(404).json({ error: 'Tenant record not found.' });
  if (tenant.get('tenantUid')) return res.status(409).json({ error: 'This tenant already has a login account.' });

  const codesRef = db.collection('tenantAccessCodes');
  const code = makeTenantCode();
  const codeHash = hash(`tenant-access:${code}`);
  const codeRef = codesRef.doc(codeHash);
  await codeRef.create({
    codeHash, landlordUid: req.user.uid, tenantId, used: false,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    expiresAt: admin.firestore.Timestamp.fromMillis(Date.now() + 7 * 24 * 60 * 60 * 1000)
  });
  return res.status(201).json({ code, expiresInDays: 7 });
}));

app.post('/api/tenants/register', tenantRegisterLimit, asyncRoute(async (req, res) => {
  const code = String(req.body.code || '').trim().toUpperCase();
  let phone;
  try { phone = normalizePhone(req.body.phone); }
  catch (error) { return res.status(400).json({ error: error.message }); }
  const password = String(req.body.password || '');
  if (!/^[A-HJ-NP-Z2-9]{8}$/.test(code)) return res.status(400).json({ error: 'Enter the eight-character code from your landlord.' });
  if (password.length < 8 || password.length > 128) return res.status(400).json({ error: 'Choose a password with at least 8 characters.' });

  const codeHash = hash(`tenant-access:${code}`);
  const codeRef = db.collection('tenantAccessCodes').doc(codeHash);
  const codeDoc = await codeRef.get();
  if (!codeDoc.exists || codeDoc.get('used') || codeDoc.get('expiresAt').toMillis() <= Date.now()) return res.status(400).json({ error: 'This code is invalid, expired, or already used. Ask your landlord for a new one.' });
  const data = codeDoc.data();
  const tenantRef = db.collection('landlords').doc(data.landlordUid).collection('tenants').doc(data.tenantId);
  const tenant = await tenantRef.get();
  if (!tenant.exists || tenant.get('tenantUid')) return res.status(409).json({ error: 'This tenant record already has an account or is unavailable.' });
  let tenantPhone;
  try { tenantPhone = normalizePhone(tenant.get('phone')); }
  catch { return res.status(409).json({ error: 'The landlord needs to add a valid phone number to your tenant record first.' }); }
  if (phone !== tenantPhone) return res.status(403).json({ error: 'Use the phone number the landlord registered for you.' });
  const credentialsRef = db.collection('tenantCredentials').doc(phoneKey(phone));
  if ((await credentialsRef.get()).exists) return res.status(409).json({ error: 'This phone number already has a tenant login. Contact your landlord for help.' });
  const authUid = `tenant_${crypto.randomUUID().replace(/-/g, '')}`;
  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = hashPassword(password, salt).toString('hex');
  let user;
  try { user = await admin.auth().createUser({ uid: authUid, displayName: String(tenant.get('fullName') || '').slice(0, 120) }); }
  catch (error) { if (error.code === 'auth/uid-already-exists') return res.status(409).json({ error: 'Please request a new setup code from your landlord.' }); throw error; }
  let failure = '';
  try {
    await db.runTransaction(async transaction => {
      const [freshCode, freshTenant, freshCredentials] = await Promise.all([transaction.get(codeRef), transaction.get(tenantRef), transaction.get(credentialsRef)]);
      if (!freshCode.exists || freshCode.get('used') || freshCode.get('expiresAt').toMillis() <= Date.now()) { failure = 'This code expired or was already used. Ask your landlord for a new one.'; return; }
      if (!freshTenant.exists || freshTenant.get('tenantUid')) { failure = 'This tenant record already has an account or is unavailable.'; return; }
      try { if (normalizePhone(freshTenant.get('phone')) !== phone) { failure = 'The phone number on the tenant record changed. Ask your landlord for a new code.'; return; } }
      catch { failure = 'The phone number on the tenant record is no longer valid. Ask your landlord for help.'; return; }
      if (freshCredentials.exists) { failure = 'This phone number already has a tenant login. Contact your landlord for help.'; return; }
      transaction.update(codeRef, { used: true, usedAt: admin.firestore.FieldValue.serverTimestamp(), tenantUid: user.uid });
      transaction.update(tenantRef, { tenantUid: user.uid, accountCreatedAt: admin.firestore.FieldValue.serverTimestamp(), updatedAt: admin.firestore.FieldValue.serverTimestamp() });
      transaction.create(credentialsRef, { authUid: user.uid, landlordUid: data.landlordUid, tenantId: data.tenantId, salt, passwordHash, failedAttempts: 0, lockedUntil: null, createdAt: admin.firestore.FieldValue.serverTimestamp() });
    });
    if (failure) throw new Error(failure);
  } catch (error) {
    await admin.auth().deleteUser(user.uid).catch(() => {});
    if (failure) return res.status(409).json({ error: failure });
    throw error;
  }
  return res.status(201).json({ registered: true });
}));

app.post('/api/tenants/login', tenantLoginLimit, asyncRoute(async (req, res) => {
  let phone;
  try { phone = normalizePhone(req.body.phone); }
  catch { return res.status(401).json({ error: 'Invalid phone number or password.' }); }
  const password = String(req.body.password || '');
  if (password.length > 128) return res.status(401).json({ error: 'Invalid phone number or password.' });
  const ref = db.collection('tenantCredentials').doc(phoneKey(phone));
  const doc = await ref.get();
  if (!doc.exists) return res.status(401).json({ error: 'Invalid phone number or password.' });
  const data = doc.data();
  const activeTenant = await db.collection('landlords').doc(data.landlordUid).collection('tenants').doc(data.tenantId).get();
  if (!activeTenant.exists || activeTenant.get('tenantUid') !== data.authUid) {
    await admin.auth().updateUser(data.authUid, { disabled: true }).catch(() => {});
    await ref.delete().catch(() => {});
    return res.status(401).json({ error: 'This tenant login is no longer active. Contact your landlord.' });
  }
  if (data.lockedUntil?.toMillis?.() > Date.now()) return res.status(429).json({ error: 'Too many tries. Please wait 15 minutes before trying again.' });
  const candidate = hashPassword(password, data.salt);
  const expected = Buffer.from(data.passwordHash, 'hex');
  if (candidate.length !== expected.length || !crypto.timingSafeEqual(candidate, expected)) {
    await db.runTransaction(async transaction => {
      const current = await transaction.get(ref);
      if (!current.exists) return;
      const attempts = Number(current.get('failedAttempts') || 0) + 1;
      transaction.update(ref, { failedAttempts: attempts >= 5 ? 0 : attempts, lockedUntil: attempts >= 5 ? admin.firestore.Timestamp.fromMillis(Date.now() + 15 * 60 * 1000) : null });
    });
    return res.status(401).json({ error: 'Invalid phone number or password.' });
  }
  await ref.update({ failedAttempts: 0, lockedUntil: null });
  const customToken = await admin.auth().createCustomToken(data.authUid);
  return res.json({ customToken });
}));

app.post('/api/tenants/revoke', requireAuth, asyncRoute(async (req, res) => {
  const tenantId = String(req.body.tenantId || '').trim();
  if (!/^[A-Za-z0-9_-]{1,150}$/.test(tenantId)) return res.status(400).json({ error: 'Choose a valid tenant record.' });
  const tenantRef = db.collection('landlords').doc(req.user.uid).collection('tenants').doc(tenantId);
  const tenant = await tenantRef.get();
  if (!tenant.exists) return res.status(404).json({ error: 'Tenant record not found.' });
  const tenantUid = tenant.get('tenantUid');
  if (!tenantUid) return res.json({ revoked: false });
  await admin.auth().updateUser(tenantUid, { disabled: true }).catch(error => { if (error.code !== 'auth/user-not-found') throw error; });
  const credentials = await db.collection('tenantCredentials').where('authUid', '==', tenantUid).limit(1).get();
  if (!credentials.empty) await credentials.docs[0].ref.delete();
  await tenantRef.update({ tenantUid: admin.firestore.FieldValue.delete(), tenantAccessRevokedAt: admin.firestore.FieldValue.serverTimestamp(), updatedAt: admin.firestore.FieldValue.serverTimestamp() });
  return res.json({ revoked: true });
}));

app.post('/api/tenants/payment-submissions', requireAuth, asyncRoute(async (req, res) => {
  const receiptCode = String(req.body.receiptCode || '').trim().toUpperCase();
  const smsText = String(req.body.smsText || '').trim().slice(0, 2000);
  const amount = Number(req.body.amount);
  if (!/^[A-Z0-9]{8,12}$/.test(receiptCode)) return res.status(400).json({ error: 'Enter the M-Pesa transaction code from the message.' });
  if (!Number.isSafeInteger(amount) || amount < 1) return res.status(400).json({ error: 'Enter a valid amount paid.' });
  if (smsText.length < 12 || !smsText.toUpperCase().includes(receiptCode)) return res.status(400).json({ error: 'Paste the full M-Pesa message and make sure it includes the transaction code.' });

  const tenantQuery = await db.collectionGroup('tenants').where('tenantUid', '==', req.user.uid).limit(1).get();
  if (tenantQuery.empty) return res.status(403).json({ error: 'Your tenant login is no longer active.' });
  const tenantDoc = tenantQuery.docs[0];
  const tenant = tenantDoc.data();
  const landlordUid = tenantDoc.ref.parent.parent.id;
  const rent = Number(tenant.monthlyRent || 0), water = Number(tenant.waterBill || 0), power = Number(tenant.powerBill || 0);
  const expectedTotal = rent + water + power;
  if (amount !== expectedTotal) return res.status(400).json({ error: `Enter the full current balance of KSh ${expectedTotal.toLocaleString('en-KE')}. For a different or partial amount, contact your landlord.` });
  const cycleDueAt = tenant.nextDueAt || null;
  if (!cycleDueAt) return res.status(409).json({ error: 'Your rent due date is missing. Ask your landlord to update your tenant record.' });

  const paymentRef = db.collection('landlords').doc(landlordUid).collection('payments').doc();
  const receiptRef = db.collection('mpesaReceiptClaims').doc(crypto.createHash('sha256').update(receiptCode).digest('hex'));
  let duplicate = false;
  await db.runTransaction(async transaction => {
    const receipt = await transaction.get(receiptRef);
    if (receipt.exists) { duplicate = true; return; }
    transaction.create(receiptRef, { landlordUid, tenantUid: req.user.uid, paymentId: paymentRef.id, createdAt: admin.firestore.FieldValue.serverTimestamp() });
    transaction.create(paymentRef, {
      tenantId: tenantDoc.id, tenantUid: req.user.uid, tenantName: tenant.fullName || '',
      tenantPhone: tenant.phone || '', houseNumber: tenant.houseNumber || '',
      amount, expectedTotal, cycleDueAt, receiptCode, smsText,
      status: 'pending', submittedAt: admin.firestore.FieldValue.serverTimestamp()
    });
  });
  if (duplicate) return res.status(409).json({ error: 'That M-Pesa transaction code has already been submitted.' });
  return res.status(201).json({ submitted: true, status: 'pending' });
}));

app.get('/api/landlords/payment-instructions', (req, res) => {
  const accountNumber = String(process.env.EQUITY_ACCOUNT_NUMBER || '0726387275').trim();
  if (!/^\d{5,20}$/.test(accountNumber)) return res.status(503).json({ error: 'Equity payment instructions are not configured yet. Please contact Fednice Solutions.' });
  return res.json({ amount: Number(process.env.LANDLORD_REGISTRATION_AMOUNT || 1000), provider: 'equity', paybill: '247247', accountNumber });
});

app.post('/api/landlords/payment-verifications', rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: 'Too many payment checks. Please wait and try again.' }), asyncRoute(async (req, res) => {
  if (!/^\d{5,20}$/.test(String(process.env.EQUITY_ACCOUNT_NUMBER || '0726387275').trim())) return res.status(503).json({ error: 'Equity payment instructions are not configured yet. Please contact Fednice Solutions.' });
  const receiptCode = String(req.body.receiptCode || '').trim().toUpperCase();
  const smsText = String(req.body.smsText || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  let phone;
  try { phone = normalizePhone(req.body.phone); }
  catch { return res.status(400).json({ error: 'Enter the Kenyan phone number used for this registration.' }); }
  if (!/^[A-Z0-9]{8,12}$/.test(receiptCode) || smsText.length < 20 || !smsText.toUpperCase().replace(/\s/g, '').includes(receiptCode)) {
    return res.status(400).json({ error: 'Paste the original M-Pesa message and enter the receipt code exactly as shown.' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Enter the email address you used on the registration page.' });

  const verificationId = crypto.randomUUID();
  const receiptHash = crypto.createHash('sha256').update(receiptCode).digest('hex');
  const verificationRef = db.collection('landlordPaymentVerifications').doc(verificationId);
  const claimRef = db.collection('landlordPaymentClaims').doc(receiptHash);
  let duplicate = false;
  let existingVerificationId = '';
  let existingStatus = '';
  await db.runTransaction(async transaction => {
    const claim = await transaction.get(claimRef);
    if (claim.exists) {
      const previousId = String(claim.get('verificationId') || '');
      if (!previousId) { duplicate = true; return; }
      const previousRef = db.collection('landlordPaymentVerifications').doc(previousId);
      const previous = await transaction.get(previousRef);
      if (!previous.exists) { duplicate = true; return; }
      if (previous.get('emailHash') === crypto.createHash('sha256').update(email).digest('hex') && ['pending_review','paid','registered'].includes(previous.get('status'))) {
        existingVerificationId = previousId;
        existingStatus = previous.get('status');
        return;
      }
      if (!['rejected','error','timeout'].includes(previous.get('status'))) { duplicate = true; return; }
      transaction.update(claimRef, { verificationId, status: 'pending_review', createdAt: admin.firestore.FieldValue.serverTimestamp() });
    } else {
      transaction.create(claimRef, { verificationId, status: 'pending_review', createdAt: admin.firestore.FieldValue.serverTimestamp() });
    }
    transaction.create(verificationRef, {
      receiptCode, amountExpected: Number(process.env.LANDLORD_REGISTRATION_AMOUNT || 1000),
      emailHash: crypto.createHash('sha256').update(email).digest('hex'), email,
      phone,
      smsText: smsText.slice(0, 2000),
      status: 'pending_review', createdAt: admin.firestore.FieldValue.serverTimestamp(),
      expiresAt: admin.firestore.Timestamp.fromMillis(Date.now() + 7 * 24 * 60 * 60 * 1000)
    });
  });
  if (existingVerificationId) return res.status(202).json({ verificationId: existingVerificationId, status: existingStatus });
  if (duplicate) return res.status(409).json({ error: 'This M-Pesa receipt has already been used for a payment check.' });

  return res.status(202).json({ verificationId, status: 'pending_review' });
}));

function requirePaymentReviewer(req, res, next) {
  const allowed = String(process.env.PAYMENT_REVIEWER_EMAILS || '').split(',').map(value => value.trim().toLowerCase()).filter(Boolean);
  if (!allowed.length) return res.status(503).json({ error: 'Payment review is not configured. Contact the system administrator.' });
  requireAuth(req, res, () => {
    if (!req.user.email || !allowed.includes(req.user.email.toLowerCase())) return res.status(403).json({ error: 'You are not allowed to review payments.' });
    next();
  });
}
app.get('/api/admin/landlord-payment-verifications', requirePaymentReviewer, asyncRoute(async (req, res) => {
  const snapshot = await db.collection('landlordPaymentVerifications').where('status', '==', 'pending_review').limit(100).get();
  return res.json({ payments: snapshot.docs.map(doc => {
    const data = doc.data();
    return { id: doc.id, receiptCode: data.receiptCode, smsText: data.smsText || '', amountExpected: data.amountExpected, email: data.email || '', phone: data.phone || '', submittedAt: data.createdAt?.toDate?.().toISOString() || null };
  }) });
}));
app.post('/api/admin/landlord-payment-verifications/:verificationId/review', requirePaymentReviewer, asyncRoute(async (req, res) => {
  const id = String(req.params.verificationId || '');
  const decision = String(req.body.decision || '');
  if (!/^[a-f0-9-]{36}$/i.test(id) || !['approve', 'reject'].includes(decision)) return res.status(400).json({ error: 'Invalid payment review request.' });
  const ref = db.collection('landlordPaymentVerifications').doc(id);
  let failure = '';
  await db.runTransaction(async transaction => {
    const payment = await transaction.get(ref);
    if (!payment.exists || payment.get('status') !== 'pending_review') { failure = 'This payment is no longer waiting for review.'; return; }
    const status = decision === 'approve' ? 'paid' : 'rejected';
    transaction.update(ref, {
      status, reviewedBy: req.user.email.toLowerCase(), reviewedAt: admin.firestore.FieldValue.serverTimestamp(),
      ...(decision === 'approve' ? { paidAt: admin.firestore.Timestamp.now(), verifiedAmount: Number(payment.get('amountExpected')), verifiedReceipt: payment.get('receiptCode') } : { failureReason: 'Payment was not confirmed in the Equity account.' })
    });
    const claimRef = db.collection('landlordPaymentClaims').doc(crypto.createHash('sha256').update(payment.get('receiptCode')).digest('hex'));
    transaction.update(claimRef, { status, updatedAt: admin.firestore.FieldValue.serverTimestamp() });
  });
  if (failure) return res.status(409).json({ error: failure });
  return res.json({ reviewed: true, status: decision === 'approve' ? 'paid' : 'rejected' });
}));

app.get('/api/landlords/payment-verifications/:verificationId', rateLimit({ windowMs: 15 * 60 * 1000, max: 120, message: 'Too many status checks. Please wait and refresh.' }), asyncRoute(async (req, res) => {
  if (!/^[a-f0-9-]{36}$/i.test(req.params.verificationId)) return res.status(404).json({ error: 'Payment check not found.' });
  const doc = await db.collection('landlordPaymentVerifications').doc(req.params.verificationId).get();
  if (!doc.exists) return res.status(404).json({ error: 'Payment check not found.' });
  const data = doc.data();
  if (data.expiresAt.toMillis() <= Date.now() && !['paid','rejected','registered'].includes(data.status)) return res.json({ status: 'timeout' });
  return res.json({ status: data.status });
}));

app.post('/api/landlords/register-paid', requireAuth, asyncRoute(async (req, res) => {
  const verificationId = String(req.body.paymentVerificationId || '');
  const profile = req.body.profile || {};
  if (!/^[a-f0-9-]{36}$/i.test(verificationId)) return res.status(400).json({ error: 'Complete the M-Pesa payment check first.' });
  if (!req.user.email || !req.user.uid) return res.status(401).json({ error: 'Please sign in again.' });
  const emailHash = crypto.createHash('sha256').update(req.user.email.toLowerCase()).digest('hex');
  const verificationRef = db.collection('landlordPaymentVerifications').doc(verificationId);
  const landlordRef = db.collection('landlords').doc(req.user.uid);
  let failure = '';
  let alreadyCreated = false;
  await db.runTransaction(async transaction => {
    const [verification, landlord] = await Promise.all([transaction.get(verificationRef), transaction.get(landlordRef)]);
    if (landlord.exists) { alreadyCreated = landlord.get('email') === req.user.email.toLowerCase(); return; }
    if (!verification.exists || verification.get('status') !== 'paid' || verification.get('emailHash') !== emailHash || verification.get('registered')) { failure = 'The verified payment is not linked to this registration. Please restart registration or contact Fednice.'; return; }
    let phone;
    try { phone = normalizePhone(profile.phone); } catch { failure = 'Enter a valid Kenyan mobile number.'; return; }
    if (phone !== verification.get('phone')) { failure = 'The registration phone number does not match the M-Pesa payer. Start again using the same phone number.'; return; }
    const safeProfile = {
      fullName: String(profile.fullName || '').trim().slice(0, 120), email: req.user.email.toLowerCase(), phone,
      idNo: String(profile.idNo || '').trim().slice(0, 20), county: String(profile.county || '').slice(0, 80),
      constituency: String(profile.constituency || '').slice(0, 80), propertyName: String(profile.propertyName || '').trim().slice(0, 120),
      subscriptionStatus: 'active', subscriptionStartedAt: verification.get('paidAt'),
      subscriptionEndsAt: admin.firestore.Timestamp.fromMillis(verification.get('paidAt').toMillis() + 90 * 24 * 60 * 60 * 1000),
      emailVerificationRequired: true,
      registrationPaymentId: verificationId, registrationPaymentAmount: verification.get('verifiedAmount'),
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    };
    if (!safeProfile.fullName || !safeProfile.idNo || !safeProfile.county || !safeProfile.constituency || !safeProfile.propertyName) { failure = 'Please complete all required landlord details.'; return; }
    transaction.create(landlordRef, safeProfile);
    transaction.update(verificationRef, { status: 'registered', registered: true, landlordUid: req.user.uid, registeredAt: admin.firestore.FieldValue.serverTimestamp() });
  });
  if (failure) return res.status(403).json({ error: failure });
  return res.status(alreadyCreated ? 200 : 201).json({ created: true });
}));

app.post('/api/landlords/payment-submissions/:paymentId/review', requireAuth, asyncRoute(async (req, res) => {
  const paymentId = String(req.params.paymentId || '');
  if (!/^[A-Za-z0-9_-]{1,150}$/.test(paymentId)) return res.status(400).json({ error: 'Invalid payment submission.' });
  const decision = String(req.body.decision || '');
  if (!['confirmed', 'rejected'].includes(decision)) return res.status(400).json({ error: 'Choose confirm or reject.' });
  const paymentRef = db.collection('landlords').doc(req.user.uid).collection('payments').doc(paymentId);
  let failure = '';
  let thankYouSms = null;
  await db.runTransaction(async transaction => {
    const payment = await transaction.get(paymentRef);
    if (!payment.exists || payment.get('status') !== 'pending') { failure = 'This payment is no longer waiting for review.'; return; }
    const tenantRef = db.collection('landlords').doc(req.user.uid).collection('tenants').doc(String(payment.get('tenantId') || ''));
    const tenant = await transaction.get(tenantRef);
    if (!tenant.exists || tenant.get('tenantUid') !== payment.get('tenantUid')) { failure = 'The linked tenant account is no longer active.'; return; }
    if (decision === 'confirmed') {
      const currentDue = tenant.get('nextDueAt');
      const submittedDue = payment.get('cycleDueAt');
      if (!currentDue || !submittedDue || currentDue.toMillis() !== submittedDue.toMillis()) { failure = 'This payment is for an older rent cycle. Review it against the M-Pesa statement before updating rent.'; return; }
      const nextDue = currentDue.toDate();
      nextDue.setDate(nextDue.getDate() + 30);
      thankYouSms = {
        phone: tenant.get('phone'),
        tenantName: tenant.get('fullName') || payment.get('tenantName') || 'Tenant',
        houseNumber: tenant.get('houseNumber') || payment.get('houseNumber') || 'your house',
        amount: Number(payment.get('amount') || 0),
        nextDueAt: nextDue
      };
      transaction.update(tenantRef, {
        nextDueAt: admin.firestore.Timestamp.fromDate(nextDue), lastPaymentAt: admin.firestore.FieldValue.serverTimestamp(),
        lastPaymentAmount: payment.get('amount'), lastPaymentStatus: 'confirmed', lastPaidCycleDueAt: currentDue,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
    }
    transaction.update(paymentRef, {
      status: decision, reviewedAt: admin.firestore.FieldValue.serverTimestamp(), reviewedBy: req.user.uid,
      ...(decision === 'confirmed' ? { thankYouSmsStatus: process.env.AT_PAYMENT_THANK_YOU === 'true' ? 'sending' : 'disabled' } : {})
    });
  });
  if (failure) return res.status(409).json({ error: failure });
  let thankYouSmsStatus = decision === 'confirmed' ? 'disabled' : null;
  if (decision === 'confirmed' && process.env.AT_PAYMENT_THANK_YOU === 'true') {
    try {
      const phone = normalizePhone(thankYouSms.phone);
      const dueDate = thankYouSms.nextDueAt.toLocaleDateString('en-KE', { day: 'numeric', month: 'long', year: 'numeric', timeZone: 'Africa/Nairobi' });
      const message = `FEDNICE: Hello ${String(thankYouSms.tenantName).slice(0, 80)}, your payment of KSh ${thankYouSms.amount.toLocaleString('en-KE')} for ${String(thankYouSms.houseNumber).slice(0, 60)} is confirmed. Thank you! Your next rent is due ${dueDate}.`;
      await sms.send({ to: [phone], message, ...(process.env.AT_SENDER_ID ? { from: process.env.AT_SENDER_ID } : {}) });
      thankYouSmsStatus = 'provider_accepted';
    } catch (error) {
      thankYouSmsStatus = 'failed';
      console.error('Payment thank-you SMS request failed:', error.message);
    }
    await paymentRef.update({ thankYouSmsStatus, thankYouSmsUpdatedAt: admin.firestore.FieldValue.serverTimestamp() }).catch(error => {
      console.error('Could not save payment thank-you SMS status:', error.message);
    });
  }
  return res.json({ reviewed: true, status: decision, tenantThankYou: decision === 'confirmed', thankYouSmsStatus });
}));

app.get('/api/landlords/payment-submissions', requireAuth, asyncRoute(async (req, res) => {
  const snapshot = await db.collection('landlords').doc(req.user.uid).collection('payments').get();
  const submissions = snapshot.docs.map(doc => {
    const data = doc.data();
    return {
      id: doc.id, tenantId: data.tenantId, tenantName: data.tenantName, tenantPhone: data.tenantPhone,
      houseNumber: data.houseNumber, amount: data.amount, expectedTotal: data.expectedTotal,
      receiptCode: data.receiptCode, smsText: data.smsText, status: data.status,
      thankYouSmsStatus: data.thankYouSmsStatus || null,
      submittedAt: data.submittedAt?.toDate?.().toISOString() || null,
      reviewedAt: data.reviewedAt?.toDate?.().toISOString() || null
    };
  }).sort((a,b) => String(b.submittedAt || '').localeCompare(String(a.submittedAt || ''))).slice(0,30);
  return res.json({ submissions });
}));

app.get('/api/tenants/me', requireAuth, asyncRoute(async (req, res) => {
  const match = await db.collectionGroup('tenants').where('tenantUid', '==', req.user.uid).limit(1).get();
  if (match.empty) return res.status(404).json({ error: 'No tenant account is linked to this login.' });
  const tenantDoc = match.docs[0];
  const landlordUid = tenantDoc.ref.parent.parent.id;
  const houseId = String(tenantDoc.get('houseId') || '').trim();
  const [landlord, house, paymentSnapshot] = await Promise.all([
    db.collection('landlords').doc(landlordUid).get(),
    houseId ? db.collection('landlords').doc(landlordUid).collection('houses').doc(houseId).get() : Promise.resolve(null),
    db.collection('landlords').doc(landlordUid).collection('payments').where('tenantId', '==', tenantDoc.id).get()
  ]);
  const data = tenantDoc.data();
  const payments = paymentSnapshot.docs.map(doc => {
    const payment = doc.data();
    return { id: doc.id, amount: payment.amount, status: payment.status, submittedAt: payment.submittedAt?.toDate?.().toISOString() || null, reviewedAt: payment.reviewedAt?.toDate?.().toISOString() || null };
  }).sort((a,b) => String(b.submittedAt || '').localeCompare(String(a.submittedAt || ''))).slice(0,10);
  return res.json({
    fullName: data.fullName || '', phone: data.phone || '', houseNumber: house?.exists ? house.get('houseNumber') : data.houseNumber || '',
    monthlyRent: Number(data.monthlyRent || (house?.exists ? house.get('monthlyRent') : 0) || 0),
    waterBill: data.waterBill ?? null, powerBill: data.powerBill ?? null,
    joinedAt: data.joinedAt?.toDate?.().toISOString() || null,
    nextDueAt: data.nextDueAt?.toDate?.().toISOString() || null,
    propertyName: landlord.exists ? landlord.get('propertyName') || 'Your landlord' : 'Your landlord',
    landlordPhone: landlord.exists ? landlord.get('phone') || '' : '', payments
  });
}));

app.post('/api/activation/send', (req, res) => res.status(410).json({ error: 'Phone-code activation has been replaced by M-Pesa payment and email verification.' }));
app.post('/api/activation/verify', (req, res) => res.status(410).json({ error: 'Phone-code activation has been replaced by M-Pesa payment and email verification.' }));
app.post('/api/landlords/register', (req, res) => res.status(410).json({ error: 'Use the payment-first landlord registration flow.' }));

app.get('/api/landlords/me', requireAuth, asyncRoute(async (req, res) => {
  const doc = await db.collection('landlords').doc(req.user.uid).get();
  if (!doc.exists) return res.status(404).json({ error: 'No activated landlord profile was found.' });
  const data = doc.data();
  if (data.emailVerificationRequired && !req.user.email_verified) return res.status(403).json({ error: 'Verify your email before opening the landlord dashboard.' });
  return res.json({ uid: req.user.uid, fullName: data.fullName, email: data.email, propertyName: data.propertyName, subscriptionStatus: data.subscriptionStatus, trialEndsAt: data.trialEndsAt?.toDate?.().toISOString() || null, subscriptionEndsAt: data.subscriptionEndsAt?.toDate?.().toISOString() || null });
}));

app.use((error, req, res, next) => {
  console.error('Request failed:', error.message);
  res.status(500).json({ error: 'Something went wrong. Please try again.' });
});
const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`FEDNICE activation API listening on ${port}`));
