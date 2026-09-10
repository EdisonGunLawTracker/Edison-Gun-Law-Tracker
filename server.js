/**
 * Edison Gun Law Tracker — backend
 * -----------------------------------------------------------------------
 * Real accounts, real password hashing (bcrypt), real signed sessions (JWT),
 * and one admin-only route that only the account matching ADMIN_EMAIL can use.
 *
 * Storage: a single JSON file (data.json) next to this script. That's enough
 * for a small user base and zero setup — no database server to run. If this
 * app ever gets real traffic, swap loadDB()/saveDB() for a real database
 * (Postgres via Supabase/Neon is a easy, free-tier-friendly next step) —
 * everything else in this file stays the same.
 *
 * Setup:
 *   1. npm install
 *   2. copy .env.example to .env and fill in JWT_SECRET and ADMIN_EMAIL
 *   3. npm start
 *
 * See README.md for how to deploy this somewhere with a public URL.
 */

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'change-this-before-you-deploy';
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || '').toLowerCase().trim();
const LEGISCAN_API_KEY = process.env.LEGISCAN_API_KEY || '';
const COURTLISTENER_API_TOKEN = process.env.COURTLISTENER_API_TOKEN || '';
const DB_FILE = path.join(__dirname, 'data.json');

if(JWT_SECRET === 'change-this-before-you-deploy'){
  console.warn('WARNING: JWT_SECRET is not set — set it in your environment before going live.');
}

function loadDB(){
  if(!fs.existsSync(DB_FILE)) return { users: [], streaks: {} };
  try{ return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch(e){ return { users: [], streaks: {} }; }
}
function saveDB(db){
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function publicUser(u){
  return { id: u.id, email: u.email, displayName: u.displayName, isAdmin: !!u.isAdmin, createdAt: u.createdAt };
}

function authMiddleware(req, res, next){
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if(!token) return res.status(401).json({ error: 'Not signed in.' });
  try{
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  }catch(e){
    return res.status(401).json({ error: 'Session expired or invalid — sign in again.' });
  }
}

function adminMiddleware(req, res, next){
  if(!req.user || !req.user.isAdmin) return res.status(403).json({ error: 'Admins only.' });
  next();
}

app.get('/api/health', (req, res) => res.json({ ok: true }));

/* ---------------- Auth ---------------- */
app.post('/api/register', (req, res) => {
  const { email, password, displayName } = req.body || {};
  const emailLower = String(email || '').toLowerCase().trim();
  if(!emailLower || !password || String(password).length < 6){
    return res.status(400).json({ error: 'A valid email and a password of at least 6 characters are required.' });
  }
  const db = loadDB();
  if(db.users.find(u => u.email === emailLower)){
    return res.status(409).json({ error: 'That email is already registered — try logging in instead.' });
  }
  const name = String(displayName || emailLower.split('@')[0]).trim().slice(0, 24) || 'Anonymous';
  const isAdmin = !!(ADMIN_EMAIL && emailLower === ADMIN_EMAIL);
  const user = {
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
    email: emailLower,
    displayName: name,
    passwordHash: bcrypt.hashSync(String(password), 10),
    isAdmin,
    createdAt: new Date().toISOString(),
  };
  db.users.push(user);
  saveDB(db);
  const token = jwt.sign(publicUser(user), JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: publicUser(user) });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  const emailLower = String(email || '').toLowerCase().trim();
  const db = loadDB();
  const user = db.users.find(u => u.email === emailLower);
  if(!user || !bcrypt.compareSync(String(password || ''), user.passwordHash)){
    return res.status(401).json({ error: 'Incorrect email or password.' });
  }
  const token = jwt.sign(publicUser(user), JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: publicUser(user) });
});

app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

/* ---------------- Daily streak + leaderboard ---------------- */
app.get('/api/leaderboard', (req, res) => {
  const db = loadDB();
  const rows = Object.entries(db.streaks)
    .map(([userId, s]) => {
      const user = db.users.find(u => u.id === userId);
      return user ? { name: user.displayName, streak: s.streak || 0, longestStreak: s.longestStreak || 0 } : null;
    })
    .filter(Boolean)
    .sort((a, b) => b.streak - a.streak || b.longestStreak - a.longestStreak)
    .slice(0, 25);
  res.json({ leaderboard: rows });
});

app.post('/api/streak', authMiddleware, (req, res) => {
  const { correct, date } = req.body || {};
  if(!date) return res.status(400).json({ error: 'Missing date.' });
  const db = loadDB();
  const prev = db.streaks[req.user.id] || { lastDate: null, streak: 0, longestStreak: 0, totalAnswered: 0, totalCorrect: 0 };

  if(prev.lastDate === date){
    return res.json({ progress: prev }); // already answered today — don't double count
  }
  const yest = (() => {
    const d = new Date(date + 'T00:00:00');
    d.setDate(d.getDate() - 1);
    return d.toISOString().slice(0, 10);
  })();

  const updated = {
    lastDate: date,
    streak: correct ? (prev.lastDate === yest ? prev.streak + 1 : 1) : 0,
    totalAnswered: (prev.totalAnswered || 0) + 1,
    totalCorrect: (prev.totalCorrect || 0) + (correct ? 1 : 0),
  };
  updated.longestStreak = Math.max(prev.longestStreak || 0, updated.streak);

  db.streaks[req.user.id] = updated;
  saveDB(db);
  res.json({ progress: updated });
});

/* ---------------- Admin only ---------------- */
// Only reachable by whichever account's email matches ADMIN_EMAIL in your
// environment variables — that's you, the developer. Everyone else gets 403.
app.get('/api/admin/users', authMiddleware, adminMiddleware, (req, res) => {
  const db = loadDB();
  res.json({
    users: db.users.map(u => ({
      ...publicUser(u),
      streak: (db.streaks[u.id] || {}).streak || 0,
      longestStreak: (db.streaks[u.id] || {}).longestStreak || 0,
    })),
  });
});

/* ---------------- LegiScan bill-tracking feed ---------------- */
// Free tier: 30,000 queries/month. We cache each state's results for 6 hours
// so a busy day of app traffic never comes close to burning through that.
// The API key lives only here on the server — it's never sent to the app.
const billsCache = {}; // { [stateAbbr]: { data: [...], ts: <ms> } }
const BILLS_CACHE_MS = 6 * 60 * 60 * 1000; // 6 hours

app.get('/api/bills', async (req, res) => {
  const state = String(req.query.state || '').toUpperCase().trim();
  if(!/^[A-Z]{2}$/.test(state)){
    return res.status(400).json({ error: 'Pass a 2-letter state code, e.g. ?state=MD.' });
  }
  if(!LEGISCAN_API_KEY){
    return res.status(503).json({ error: 'Bill tracking isn\'t configured yet (missing LEGISCAN_API_KEY).' });
  }

  const cached = billsCache[state];
  if(cached && (Date.now() - cached.ts) < BILLS_CACHE_MS){
    return res.json({ state, bills: cached.data, cached: true });
  }

  try{
    const url = 'https://api.legiscan.com/?key=' + encodeURIComponent(LEGISCAN_API_KEY)
      + '&op=getSearch&state=' + encodeURIComponent(state)
      + '&query=' + encodeURIComponent('firearm');
    const r = await fetch(url);
    const json = await r.json();

    if(json.status !== 'OK' || !json.searchresult){
      return res.status(502).json({ error: 'LegiScan did not return results for that state.' });
    }

    const bills = Object.values(json.searchresult)
      .filter(item => item && typeof item === 'object' && item.bill_id)
      .map(item => ({
        billNumber: item.bill_number,
        title: item.title,
        lastAction: item.last_action,
        lastActionDate: item.last_action_date,
        url: item.url,
        relevance: item.relevance,
      }))
      .sort((a, b) => (b.lastActionDate || '').localeCompare(a.lastActionDate || ''))
      .slice(0, 8);

    billsCache[state] = { data: bills, ts: Date.now() };
    res.json({ state, bills, cached: false });
  }catch(e){
    console.error('LegiScan lookup failed:', e.message);
    res.status(502).json({ error: 'Could not reach LegiScan right now — try again shortly.' });
  }
});

/* ---------------- Recent 2A / firearm case-law feed ---------------- */
// Uses CourtListener (Free Law Project — a nonprofit, genuinely free legal
// database). Works with no API key at all (their anonymous tier), but if
// COURTLISTENER_API_TOKEN is set (free — register at courtlistener.com,
// same idea as the LegiScan key) requests are authenticated for more
// reliable access. One shared national cache, refreshed once a day —
// case law moves far slower than legislation, so there's no need to hit
// this more often or cache it per-state.
const caseLawCache = { data: null, ts: 0 };
const CASE_LAW_CACHE_MS = 24 * 60 * 60 * 1000; // 24 hours

app.get('/api/case-law', async (req, res) => {
  if(caseLawCache.data && (Date.now() - caseLawCache.ts) < CASE_LAW_CACHE_MS){
    return res.json({ cases: caseLawCache.data, cached: true });
  }

  try{
    const url = 'https://www.courtlistener.com/api/rest/v4/search/?q='
      + encodeURIComponent('"second amendment" OR firearm OR "concealed carry"')
      + '&type=o&order_by=dateFiled%20desc';
    const headers = COURTLISTENER_API_TOKEN ? { Authorization: 'Token ' + COURTLISTENER_API_TOKEN } : {};
    const r = await fetch(url, { headers });
    const json = await r.json();

    if(!json.results){
      return res.status(502).json({ error: 'CourtListener did not return results.' });
    }

    const cases = json.results.slice(0, 8).map(item => ({
      caseName: item.caseName,
      court: item.court,
      dateFiled: item.dateFiled,
      url: item.absolute_url ? ('https://www.courtlistener.com' + item.absolute_url) : null,
    }));

    caseLawCache.data = cases;
    caseLawCache.ts = Date.now();
    res.json({ cases, cached: false });
  }catch(e){
    console.error('CourtListener lookup failed:', e.message);
    res.status(502).json({ error: 'Could not reach CourtListener right now — try again shortly.' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Edison backend running on port ' + PORT));
