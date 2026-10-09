'use strict';
const crypto = require('crypto');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

function httpErr(status, message) { return Object.assign(new Error(message), { http: status }); }

// Hanya SESSION_SECRET yang wajib (plus ADMIN_USERNAME/ADMIN_PASSWORD untuk masuk). Tanpa database. Admin berasal dari env ADMIN_USERNAME + ADMIN_PASSWORD (lihat envAdmin di api.js).
function cfg() {
  const secret = process.env.SESSION_SECRET || '';
  if (secret.length < 32) throw httpErr(500, 'Server belum dikonfigurasi: isi SESSION_SECRET (minimal 32 karakter) di Environment Variables Vercel.');
  return { secret };
}

async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const h = await scrypt(pw, salt, 32);
  return 'scrypt$' + salt.toString('hex') + '$' + h.toString('hex');
}
async function verifyPassword(pw, stored) {
  try {
    const [alg, s, h] = String(stored).split('$');
    if (alg !== 'scrypt') return false;
    const calc = await scrypt(pw, Buffer.from(s, 'hex'), 32);
    const exp = Buffer.from(h, 'hex');
    return calc.length === exp.length && crypto.timingSafeEqual(calc, exp);
  } catch (e) { return false; }
}
function safeEq(a, b) {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
}

function sign(payload, secret) {
  const p = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return p + '.' + crypto.createHmac('sha256', secret).update(p).digest('base64url');
}
function verify(token, secret) {
  try {
    const [p, m] = String(token).split('.');
    if (!p || !m || !safeEq(m, crypto.createHmac('sha256', secret).update(p).digest('base64url'))) return null;
    const pl = JSON.parse(Buffer.from(p, 'base64url').toString());
    return pl.exp && pl.exp > Date.now() / 1000 ? pl : null;
  } catch (e) { return null; }
}

// API key Gemini yang disimpan admin dienkripsi AES-256-GCM, kunci diturunkan dari SESSION_SECRET.
const encKey = secret => crypto.createHash('sha256').update('franzz-orbit:enc:' + secret).digest();
function encrypt(text, secret) {
  const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', encKey(secret), iv);
  const d = Buffer.concat([c.update(text, 'utf8'), c.final()]);
  return [iv, c.getAuthTag(), d].map(x => x.toString('base64')).join('.');
}
function decrypt(s, secret) {
  try {
    const [iv, tag, d] = String(s).split('.').map(x => Buffer.from(x, 'base64'));
    const c = crypto.createDecipheriv('aes-256-gcm', encKey(secret), iv);
    c.setAuthTag(tag);
    return Buffer.concat([c.update(d), c.final()]).toString('utf8');
  } catch (e) { return null; }
}

module.exports = { httpErr, cfg, hashPassword, verifyPassword, safeEq, sign, verify, encrypt, decrypt };
