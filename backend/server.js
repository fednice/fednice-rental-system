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
