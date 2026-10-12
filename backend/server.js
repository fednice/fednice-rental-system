const crypto = require('node:crypto');
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
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
app.use(cors({ origin: process.env.CORS_ORIGIN.split(',').map(value => value.trim()), methods: ['GET', 'POST'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.use(express.json({ limit: '16kb' }));

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

app.post('/api/tenants/register', asyncRoute(async (req, res) => {
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

app.post('/api/tenants/login', asyncRoute(async (req, res) => {
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

app.get('/api/tenants/me', requireAuth, asyncRoute(async (req, res) => {
  const match = await db.collectionGroup('tenants').where('tenantUid', '==', req.user.uid).limit(1).get();
  if (match.empty) return res.status(404).json({ error: 'No tenant account is linked to this login.' });
  const tenantDoc = match.docs[0];
  const landlordUid = tenantDoc.ref.parent.parent.id;
  const [landlord, house] = await Promise.all([
    db.collection('landlords').doc(landlordUid).get(),
    db.collection('landlords').doc(landlordUid).collection('houses').doc(String(tenantDoc.get('houseId') || '')).get()
  ]);
  const data = tenantDoc.data();
  return res.json({
    fullName: data.fullName || '', phone: data.phone || '', houseNumber: house.exists ? house.get('houseNumber') : data.houseNumber || '',
    monthlyRent: Number(data.monthlyRent || (house.exists ? house.get('monthlyRent') : 0) || 0),
    waterBill: data.waterBill ?? null, powerBill: data.powerBill ?? null,
    joinedAt: data.joinedAt?.toDate?.().toISOString() || null,
    nextDueAt: data.nextDueAt?.toDate?.().toISOString() || null,
    propertyName: landlord.exists ? landlord.get('propertyName') || 'Your landlord' : 'Your landlord',
    landlordPhone: landlord.exists ? landlord.get('phone') || '' : ''
  });
}));

app.post('/api/activation/send', asyncRoute(async (req, res) => {
  let phone;
  try { phone = normalizePhone(req.body.phone); }
  catch (error) { return res.status(400).json({ error: error.message }); }
  const key = phoneKey(phone);
  const ref = db.collection('activationChallenges').doc(key);
  const old = await ref.get();
  if (old.exists && Date.now() - old.get('createdAt').toMillis() < 60000) return res.status(429).json({ error: 'Please wait one minute before requesting another code.' });
  const code = crypto.randomInt(0, 1000000).toString().padStart(6, '0');
  const createdAt = admin.firestore.Timestamp.now();
  await ref.set({ phone, codeHash: hash(`${phone}:${code}`), createdAt, expiresAt: admin.firestore.Timestamp.fromMillis(Date.now() + 5 * 60 * 1000), attempts: 0, verified: false, ticketId: null, ticketUsed: false });
  try {
    await sms.send({ to: [phone], message: `FEDNICE activation code: ${code}. Expires in 5 minutes. Do not share this code.`, ...(process.env.AT_SENDER_ID ? { from: process.env.AT_SENDER_ID } : {}) });
  } catch (error) {
    await ref.delete();
    console.error('SMS provider request failed:', error.message);
    return res.status(502).json({ error: 'The activation SMS could not be sent. Please try again shortly.' });
  }
  return res.json({ sent: true, expiresInSeconds: 300 });
}));

app.post('/api/activation/verify', asyncRoute(async (req, res) => {
  let phone;
  try { phone = normalizePhone(req.body.phone); }
  catch (error) { return res.status(400).json({ error: error.message }); }
  const code = String(req.body.code || '');
  if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: 'Enter the six-digit SMS code.' });
  const ref = db.collection('activationChallenges').doc(phoneKey(phone));
  const ticketId = crypto.randomUUID();
  let failure = '';
  await db.runTransaction(async transaction => {
    const doc = await transaction.get(ref);
    if (!doc.exists) { failure = 'No active code was found. Request a new one.'; return; }
    const data = doc.data();
    if (data.verified || data.expiresAt.toMillis() <= Date.now()) { failure = 'This code has expired or was already used. Request a new code.'; return; }
    if ((data.attempts || 0) >= 5) { failure = 'Too many attempts. Request a new code.'; return; }
    if (data.codeHash !== hash(`${phone}:${code}`)) {
      transaction.update(ref, { attempts: (data.attempts || 0) + 1 });
      failure = `Incorrect code. ${4 - (data.attempts || 0)} attempt(s) remain.`;
      return;
    }
    transaction.update(ref, { verified: true, verifiedAt: admin.firestore.Timestamp.now(), ticketId });
  });
  if (failure) return res.status(400).json({ error: failure });
  const activationTicket = jwt.sign({ phone, phoneKey: phoneKey(phone), ticketId }, process.env.OTP_SECRET, { expiresIn: '10m', issuer: 'fednice-rental-system' });
  return res.json({ activationTicket });
}));

app.post('/api/landlords/register', requireAuth, asyncRoute(async (req, res) => {
  let ticket;
  try { ticket = jwt.verify(String(req.body.activationTicket || ''), process.env.OTP_SECRET, { issuer: 'fednice-rental-system' }); }
  catch { return res.status(400).json({ error: 'Phone verification expired. Request a new activation code.' }); }
  const profile = req.body.profile || {};
  let phone;
  try { phone = normalizePhone(profile.phone); }
  catch (error) { return res.status(400).json({ error: error.message }); }
  if (phone !== ticket.phone || !req.user.email || req.user.email.toLowerCase() !== String(profile.email || '').trim().toLowerCase()) return res.status(403).json({ error: 'The verified phone or sign-in email does not match this registration.' });
  const safeProfile = {
    fullName: String(profile.fullName || '').trim().slice(0, 120), email: req.user.email.toLowerCase(), phone,
    idNo: String(profile.idNo || '').trim().slice(0, 20), county: String(profile.county || '').slice(0, 80),
    constituency: String(profile.constituency || '').slice(0, 80), propertyName: String(profile.propertyName || '').trim().slice(0, 120),
    trialStartedAt: admin.firestore.FieldValue.serverTimestamp(), trialEndsAt: admin.firestore.Timestamp.fromMillis(Date.now() + 90 * 24 * 60 * 60 * 1000),
    subscriptionStatus: 'trial', createdAt: admin.firestore.FieldValue.serverTimestamp()
  };
  if (!safeProfile.fullName || !safeProfile.idNo || !safeProfile.county || !safeProfile.constituency || !safeProfile.propertyName) return res.status(400).json({ error: 'Please complete all required landlord details.' });
  const challengeRef = db.collection('activationChallenges').doc(ticket.phoneKey);
  const landlordRef = db.collection('landlords').doc(req.user.uid);
  let conflict = false;
  await db.runTransaction(async transaction => {
    const [challenge, landlord] = await Promise.all([transaction.get(challengeRef), transaction.get(landlordRef)]);
    if (!challenge.exists || !challenge.get('verified') || challenge.get('ticketId') !== ticket.ticketId || challenge.get('ticketUsed') || challenge.get('phone') !== phone) { conflict = true; return; }
    if (landlord.exists) { conflict = true; return; }
    transaction.create(landlordRef, safeProfile);
    transaction.update(challengeRef, { ticketUsed: true, consumedAt: admin.firestore.FieldValue.serverTimestamp() });
  });
  if (conflict) return res.status(409).json({ error: 'This activation code was used already or the account already exists.' });
  return res.status(201).json({ created: true });
}));

app.get('/api/landlords/me', requireAuth, asyncRoute(async (req, res) => {
  const doc = await db.collection('landlords').doc(req.user.uid).get();
  if (!doc.exists) return res.status(404).json({ error: 'No activated landlord profile was found.' });
  const data = doc.data();
  return res.json({ uid: req.user.uid, fullName: data.fullName, email: data.email, propertyName: data.propertyName, subscriptionStatus: data.subscriptionStatus, trialEndsAt: data.trialEndsAt.toDate().toISOString() });
}));

app.use((error, req, res, next) => {
  console.error('Request failed:', error.message);
  res.status(500).json({ error: 'Something went wrong. Please try again.' });
});
const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`FEDNICE activation API listening on ${port}`));
