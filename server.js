/**
 * Edison Gun Law Tracker — backend
 * -----------------------------------------------------------------------
 * Real accounts, real password hashing (bcrypt), real signed sessions (JWT),
 * and one admin-only route that only the account matching ADMIN_EMAIL can use.
 *
 * Storage: everything lives in one JSON blob, kept in memory while the server
 * runs and mirrored to a Supabase Postgres table ("app_state") on every save.
 * That's what makes signups (and everything else) survive a restart/redeploy —
 * a plain data.json file next to this script does NOT survive that on Render
 * (or most hosts): the disk resets to the last deploy on every restart, which
 * on Render's free plan also happens automatically after ~15 minutes idle.
 * If SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY aren't set, this falls back to
 * that old local file so the app still runs — but the data-loss bug comes
 * back until those two env vars are set. See README.md for setup.
 *
 * Setup:
 *   1. npm install
 *   2. copy .env.example to .env and fill in JWT_SECRET, ADMIN_EMAIL,
 *      SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY
 *   3. In the Supabase SQL editor, run once:
 *        create table app_state (id int primary key, data jsonb not null default '{}'::jsonb);
 *   4. npm start
 *
 * See README.md for how to deploy this somewhere with a public URL.
 */

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(cors());
app.use(express.json());

/**
 * Rate limiting — added 2026-09-14, closes the "no rate limiting anywhere"
 * item flagged in Security - App Security Watch.md (finding #4, 2026-09-13).
 * Render sits behind a proxy, so req.ip needs the real client address —
 * `trust proxy` makes express-rate-limit key on the actual visitor instead
 * of Render's proxy IP for everyone at once.
 */
app.set('trust proxy', 1);

// Login/register: a real user rarely needs more than a handful of attempts
// in 15 minutes. Tight enough to blunt brute-forcing and credential-stuffing,
// loose enough that a person who fat-fingers their password a few times
// never notices this exists.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts — please wait a few minutes and try again.' },
});

// Public submission endpoints (stories, questions, ad inquiries, feedback,
// photos): generous enough for a real person submitting a handful of things,
// tight enough to stop a script from flooding the admin review queues.
const submitLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many submissions from this connection — please try again later.' },
});

const JWT_SECRET = process.env.JWT_SECRET || 'change-this-before-you-deploy';
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || '').toLowerCase().trim();
const LEGISCAN_API_KEY = process.env.LEGISCAN_API_KEY || '';
const COURTLISTENER_API_TOKEN = process.env.COURTLISTENER_API_TOKEN || '';
const DB_FILE = path.join(__dirname, 'data.json'); // fallback only — see storage note above
const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const supabase = (SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY)
  ? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } })
  : null;

if(JWT_SECRET === 'change-this-before-you-deploy'){
  console.warn('WARNING: JWT_SECRET is not set — set it in your environment before going live.');
}
if(!supabase){
  console.warn('WARNING: SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY are not set — using the local data.json file for now. On Render (and most hosts) that file is wiped on every restart/redeploy, which loses every signup made since the last one. Set those two env vars to fix this for good.');
}

function blankDB(){
  return { users: [], streaks: {}, stories: [], questions: [], adInquiries: [], feedback: [], photos: [], stateViews: {}, tabViews: {}, visits: { total: 0, uniqueIds: [] }, gameScores: {}, dailyStats: {} };
}

function applyBackCompat(db){
  if(!db || typeof db !== 'object') db = blankDB();
  if(!Array.isArray(db.users)) db.users = [];
  if(!db.streaks || typeof db.streaks !== 'object') db.streaks = {};
  if(!Array.isArray(db.stories)) db.stories = []; // back-compat with data saved before this feature existed
  if(!Array.isArray(db.questions)) db.questions = []; // back-compat with data saved before this feature existed
  if(!Array.isArray(db.adInquiries)) db.adInquiries = []; // back-compat with data saved before this feature existed
  if(!Array.isArray(db.feedback)) db.feedback = []; // back-compat with data saved before this feature existed
  if(!Array.isArray(db.photos)) db.photos = []; // back-compat with data saved before this feature existed
  if(!db.stateViews || typeof db.stateViews !== 'object') db.stateViews = {}; // back-compat
  if(!db.tabViews || typeof db.tabViews !== 'object') db.tabViews = {}; // back-compat
  if(!db.gameScores || typeof db.gameScores !== 'object') db.gameScores = {}; // back-compat — State Law Trivia + future games' scores, keyed by user id
  if(!db.visits || typeof db.visits !== 'object') db.visits = { total: 0, uniqueIds: [] }; // back-compat
  if(!Array.isArray(db.visits.uniqueIds)) db.visits.uniqueIds = [];
  if(typeof db.visits.total !== 'number') db.visits.total = 0;
  if(!db.dailyStats || typeof db.dailyStats !== 'object') db.dailyStats = {}; // back-compat — added 2026-09-21 for the admin Dashboard graphs; { 'YYYY-MM-DD': { visits, quizAnswers, quizCorrect } }, days before this change simply have no entry (charts show 0, not an error)
  db.users.forEach(u => { // back-compat with accounts created before membership existed
    if(typeof u.isMember !== 'boolean') u.isMember = false;
    if(typeof u.showOnWall !== 'boolean') u.showOnWall = false;
  });
  return db;
}

// ---- Daily stats bucket, powers the admin Dashboard graphs (added 2026-09-21) ----
// Keyed by UTC calendar day ('YYYY-MM-DD') since the server has no reliable notion of
// "Antonio's local day." Only a few counters get bumped live (visits, quiz activity) —
// signups-per-day is derived straight from each user's existing createdAt instead of
// double-tracked here, so there's only one place that can drift.
function todayKey(){
  return new Date().toISOString().slice(0, 10);
}
function bumpDaily(db, field, amount){
  const key = todayKey();
  if(!db.dailyStats[key]) db.dailyStats[key] = { visits: 0, quizAnswers: 0, quizCorrect: 0 };
  db.dailyStats[key][field] = (db.dailyStats[key][field] || 0) + amount;
  // Keep this from growing forever — 120 days is far more than the 30-day chart needs.
  const keys = Object.keys(db.dailyStats);
  if(keys.length > 120){
    keys.sort().slice(0, keys.length - 120).forEach(k => delete db.dailyStats[k]);
  }
}

function loadLocalFile(){
  if(!fs.existsSync(DB_FILE)) return blankDB();
  try{ return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch(e){ return blankDB(); }
}

// The whole app's data, kept in memory once loaded and mirrored to Supabase (or the local
// file, if Supabase isn't configured) on every save. loadDB()/saveDB() below are what every
// route in this file actually calls — same names and shapes as before, so nothing past this
// point needed to change for the move to real persistent storage.
let cachedDB = null;

async function initStorage(){
  if(supabase){
    try{
      const { data, error } = await supabase.from('app_state').select('data').eq('id', 1).maybeSingle();
      if(error) throw error;
      if(data && data.data){
        cachedDB = applyBackCompat(data.data);
      } else {
        cachedDB = blankDB();
        const { error: insertErr } = await supabase.from('app_state').upsert({ id: 1, data: cachedDB });
        if(insertErr) console.error('Could not create the initial Supabase row (does the app_state table exist?):', insertErr.message);
      }
      return;
    }catch(e){
      console.error('Could not reach Supabase on startup — using the local file for this run instead:', e.message);
    }
  }
  cachedDB = applyBackCompat(loadLocalFile());
}

function loadDB(){
  return cachedDB;
}

function saveDB(db){
  cachedDB = db;
  if(supabase){
    supabase.from('app_state').update({ data: db }).eq('id', 1).then(({ error }) => {
      if(error) console.error('Failed to save to Supabase:', error.message);
    });
  } else {
    try{ fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }
    catch(e){ console.error('Failed to save data.json:', e.message); }
  }
}

// Who's on the app right now — kept in memory only, never written to disk. It resets
// on every server restart/redeploy, which is fine: "live right now" isn't meant to be
// a historical record, just this instant.
const liveVisitors = new Map(); // visitorId -> last-seen timestamp (ms)
const LIVE_WINDOW_MS = 60 * 1000; // counted as "live" if seen in the last 60 seconds
function countLiveVisitors(){
  const cutoff = Date.now() - LIVE_WINDOW_MS;
  let count = 0;
  for(const [id, lastSeen] of liveVisitors){
    if(lastSeen >= cutoff) count++;
    else liveVisitors.delete(id); // prune while we're here, keeps the map small
  }
  return count;
}
// NOTE (2026-09-14, found during the State Law Trivia build): a second, older `function saveDB(db){...}`
// used to sit right here, writing straight to the local data.json file. In JavaScript, when two top-level
// function declarations share a name, the LAST one in the file silently wins for every call anywhere in
// the script — so that leftover copy was quietly overriding the real Supabase-mirroring saveDB() defined
// above, meaning every save since it landed has been going to the local file only, never to Supabase. That
// undoes the whole point of the Supabase migration: on the next restart/redeploy, initStorage() reloads
// whatever is still in Supabase (nothing since that leftover copy was introduced) and any signups/data
// saved since then are gone. Removed the duplicate. Antonio: this needs a redeploy to actually take effect
// in production, and is worth testing for real this time (restart the Render service and confirm a fresh
// signup survives) rather than trusting the startup log line alone, since that line was never proof this
// bug wasn't there.

function publicUser(u){
  return {
    id: u.id, email: u.email, displayName: u.displayName, isAdmin: !!u.isAdmin, isMember: !!u.isMember,
    showOnWall: !!u.showOnWall, createdAt: u.createdAt,
    bio: u.bio || '', homeState: u.homeState || '', showProfile: !!u.showProfile,
  };
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

// Like authMiddleware, but never rejects the request — it just attaches req.user when a
// valid token is present. Used on routes anyone can call, where we still want to know
// (for example) whether a submitter is a signed-in member, without requiring login.
function optionalAuth(req, res, next){
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if(token){
    try{ req.user = jwt.verify(token, JWT_SECRET); }
    catch(e){ /* invalid/expired token — proceed as anonymous, don't block the request */ }
  }
  next();
}

app.get('/api/health', (req, res) => res.json({ ok: true }));

/* ---------------- Auth ---------------- */
app.post('/api/register', authLimiter, (req, res) => {
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
    isMember: false, // members are granted manually by the admin in the Dashboard tab (no Patreon API hookup)
    showOnWall: false, // opt-in: show this name on the public Supporters Wall
    bio: '', // optional member profile — freeform, self-set, capped at 160 chars
    homeState: '', // optional member profile — 2-letter state abbreviation, self-set
    showProfile: false, // opt-in: show bio/homeState on the public member directory
    createdAt: new Date().toISOString(),
  };
  db.users.push(user);
  saveDB(db);
  const token = jwt.sign(publicUser(user), JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: publicUser(user) });
});

app.post('/api/login', authLimiter, (req, res) => {
  const { email, password } = req.body || {};
  const emailLower = String(email || '').toLowerCase().trim();
  const db = loadDB();
  const user = db.users.find(u => u.email === emailLower);
  if(!user || !bcrypt.compareSync(String(password || ''), user.passwordHash)){
    return res.status(401).json({ error: 'Incorrect email or password.' });
  }
  // Fresh login resets this account's State Law Trivia round count — see the
  // "3 rounds per login" rule on the /api/games/state-trivia/round route below.
  if(!db.gameScores[user.id]){
    db.gameScores[user.id] = { totalScore: 0, roundsPlayedSinceLogin: 0, roundsAllTime: 0, correctAllTime: 0, totalAllTime: 0, lastPlayedAt: null };
  } else {
    db.gameScores[user.id].roundsPlayedSinceLogin = 0;
  }
  saveDB(db);
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
  bumpDaily(db, 'quizAnswers', 1);
  if(correct) bumpDaily(db, 'quizCorrect', 1);
  saveDB(db);
  res.json({ progress: updated });
});

/* ---------------- Games: overall score shared across every in-app game (State Law Trivia today,
   room for more later) — separate from the daily-question streak above, which is its own thing. ---------------- */

// One round = up to 10 multiple-choice questions the frontend already graded client-side (the
// question bank is just STATES/CARRY_INFO/SD_INFO/etc. already shipped to the browser, so there's
// nothing secret to check server-side). This route just records the result and enforces the
// "3 rounds per login" rule Antonio asked for: /api/login above resets roundsPlayedSinceLogin to 0
// every time someone logs in, and this route refuses a 4th round until their next login.
app.post('/api/games/state-trivia/round', authMiddleware, (req, res) => {
  const { correct, total } = req.body || {};
  const correctNum = Number(correct), totalNum = Number(total);
  if(!Number.isInteger(correctNum) || !Number.isInteger(totalNum) || totalNum < 1 || totalNum > 10 || correctNum < 0 || correctNum > totalNum){
    return res.status(400).json({ error: 'Invalid round result.' });
  }
  const db = loadDB();
  const entry = db.gameScores[req.user.id] || { totalScore: 0, roundsPlayedSinceLogin: 0, roundsAllTime: 0, correctAllTime: 0, totalAllTime: 0, lastPlayedAt: null };
  if(entry.roundsPlayedSinceLogin >= 3){
    return res.status(403).json({ error: "You've played all 3 rounds for this login — log out and back in, or come back another time, for more." });
  }
  entry.roundsPlayedSinceLogin += 1;
  entry.roundsAllTime += 1;
  entry.correctAllTime += correctNum;
  entry.totalAllTime += totalNum;
  entry.totalScore += correctNum; // simple, transparent scoring: 1 point per correct answer, same unit every game on this leaderboard uses
  entry.lastPlayedAt = new Date().toISOString();
  db.gameScores[req.user.id] = entry;
  bumpDaily(db, 'quizAnswers', totalNum);
  bumpDaily(db, 'quizCorrect', correctNum);
  saveDB(db);
  res.json({ score: entry, roundsRemaining: Math.max(0, 3 - entry.roundsPlayedSinceLogin) });
});

// The signed-in user's own score summary — used by the Scores tab so someone who hasn't played
// yet still sees "0" instead of nothing, without that "0" ever being written to the database.
app.get('/api/games/me', authMiddleware, (req, res) => {
  const db = loadDB();
  const entry = db.gameScores[req.user.id] || { totalScore: 0, roundsPlayedSinceLogin: 0, roundsAllTime: 0, correctAllTime: 0, totalAllTime: 0, lastPlayedAt: null };
  res.json({ score: entry, roundsRemaining: Math.max(0, 3 - entry.roundsPlayedSinceLogin) });
});

// Public overall-score leaderboard — combines every game that reports into gameScores (just
// State Law Trivia for now). Same shape/pattern as /api/leaderboard above.
app.get('/api/games/leaderboard', (req, res) => {
  const db = loadDB();
  const rows = Object.entries(db.gameScores)
    .map(([userId, s]) => {
      const user = db.users.find(u => u.id === userId);
      return user && s.totalScore > 0 ? { name: user.displayName, totalScore: s.totalScore || 0 } : null;
    })
    .filter(Boolean)
    .sort((a, b) => b.totalScore - a.totalScore)
    .slice(0, 25);
  res.json({ leaderboard: rows });
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

// Membership perks (Patreon, $3.99/mo) aren't verified against Patreon itself — there's no
// API hookup for that — so this is the manual switch: check your Patreon patron list, then
// flip this on for that person's account here. It unlocks: the member badge, priority on
// submitted questions, the printable state one-pager, and (if they opt in) a line on the
// public Supporters Wall.
app.post('/api/admin/users/:id/member', authMiddleware, adminMiddleware, (req, res) => {
  const { isMember } = req.body || {};
  const db = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if(!user) return res.status(404).json({ error: 'User not found.' });
  user.isMember = !!isMember;
  if(!user.isMember) user.showOnWall = false; // no longer a member — drop them from the wall too
  saveDB(db);
  res.json({ user: publicUser(user) });
});

// Self-service: a member opts in/out of appearing on the public Supporters Wall.
app.post('/api/me/wall', authMiddleware, (req, res) => {
  const { show } = req.body || {};
  const db = loadDB();
  const user = db.users.find(u => u.id === req.user.id);
  if(!user) return res.status(404).json({ error: 'User not found.' });
  if(!user.isMember){
    return res.status(403).json({ error: 'Only members can join the Supporters Wall.' });
  }
  user.showOnWall = !!show;
  saveDB(db);
  res.json({ user: publicUser(user) });
});

// Public: first names/display names of members who opted in, oldest member first (a
// rough "founding members" ordering) — no emails, no other account details.
app.get('/api/supporters', (req, res) => {
  const db = loadDB();
  const supporters = db.users
    .filter(u => u.isMember && u.showOnWall)
    .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))
    .slice(0, 300)
    .map(u => ({ displayName: u.displayName, since: u.createdAt }));
  res.json({ supporters });
});

// Self-service: ANY signed-in user (not just paid members) can set an optional bio +
// home state and opt in/out of the public member directory below. Separate from the
// paid-member Supporters Wall above — this is free, for anyone with an account.
const VALID_STATE_ABBRS = new Set([
  'AL','AK','AZ','AR','CA','CO','CT','DE','DC','FL','GA','HI','ID','IL','IN','IA','KS','KY','LA',
  'ME','MD','MA','MI','MN','MS','MO','MT','NE','NV','NH','NJ','NM','NY','NC','ND','OH','OK','OR',
  'PA','RI','SC','SD','TN','TX','UT','VT','VA','WA','WV','WI','WY',
]);
app.post('/api/me/profile', authMiddleware, (req, res) => {
  const { bio, homeState, showProfile } = req.body || {};
  const db = loadDB();
  const user = db.users.find(u => u.id === req.user.id);
  if(!user) return res.status(404).json({ error: 'User not found.' });

  const cleanBio = String(bio || '').trim().slice(0, 160);
  const cleanState = String(homeState || '').trim().toUpperCase();
  if(cleanState && !VALID_STATE_ABBRS.has(cleanState)){
    return res.status(400).json({ error: 'That doesn\'t look like a valid state.' });
  }

  user.bio = cleanBio;
  user.homeState = cleanState;
  user.showProfile = !!showProfile;
  saveDB(db);
  res.json({ user: publicUser(user) });
});

// Public: opted-in member profiles — display name, home state, and bio only. No emails,
// no streaks, no membership status. Oldest account first, same ordering as the wall.
app.get('/api/members', (req, res) => {
  const db = loadDB();
  const members = db.users
    .filter(u => u.showProfile && (u.bio || u.homeState))
    .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))
    .slice(0, 300)
    .map(u => ({ displayName: u.displayName, homeState: u.homeState || '', bio: u.bio || '', since: u.createdAt }));
  res.json({ members });
});

/* ---------------- Pulled-over stories (community, admin-moderated) ---------------- */
// Anyone can submit — no account needed, so it's usable in the moment right after a
// stop. Nothing shows up in the public feed until an admin (ADMIN_EMAIL) approves it
// via the /api/admin/stories routes below.
function isHttpUrl(str){
  try{ const u = new URL(str); return u.protocol === 'http:' || u.protocol === 'https:'; }
  catch(e){ return false; }
}

app.post('/api/stories', submitLimiter, (req, res) => {
  const { state, story, videoLink, displayName, contactEmail, website } = req.body || {};
  if(website) return res.json({ ok: true }); // honeypot field — bots fill it, real users never see it

  const storyText = String(story || '').trim();
  if(storyText.length < 20 || storyText.length > 2000){
    return res.status(400).json({ error: 'Tell us what happened in 20–2000 characters.' });
  }
  const stateAbbr = /^[A-Za-z]{2}$/.test(String(state || '')) ? String(state).toUpperCase() : null;
  const link = String(videoLink || '').trim().slice(0, 500);
  if(link && !isHttpUrl(link)){
    return res.status(400).json({ error: 'That video link needs to start with http:// or https://.' });
  }
  const name = String(displayName || '').trim().slice(0, 40) || 'Anonymous';
  const email = String(contactEmail || '').trim().slice(0, 200);

  const db = loadDB();
  db.stories.push({
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
    state: stateAbbr,
    story: storyText,
    videoLink: link || null,
    displayName: name,
    contactEmail: email || null,
    status: 'pending',
    createdAt: new Date().toISOString(),
  });
  if(db.stories.length > 2000) db.stories = db.stories.slice(-2000); // keep the file from growing forever
  saveDB(db);
  res.json({ ok: true });
});

app.get('/api/stories', (req, res) => {
  const db = loadDB();
  const approved = db.stories
    .filter(s => s.status === 'approved')
    .slice().reverse().slice(0, 200)
    .map(s => ({ id: s.id, state: s.state, story: s.story, videoLink: s.videoLink, displayName: s.displayName, createdAt: s.createdAt }));
  res.json({ stories: approved });
});

app.get('/api/admin/stories', authMiddleware, adminMiddleware, (req, res) => {
  const db = loadDB();
  res.json({ stories: db.stories.slice().reverse() });
});

app.post('/api/admin/stories/:id/status', authMiddleware, adminMiddleware, (req, res) => {
  const { status } = req.body || {};
  if(!['pending', 'approved', 'rejected'].includes(status)){
    return res.status(400).json({ error: 'status must be pending, approved, or rejected.' });
  }
  const db = loadDB();
  const entry = db.stories.find(s => s.id === req.params.id);
  if(!entry) return res.status(404).json({ error: 'Story not found.' });
  entry.status = status;
  saveDB(db);
  res.json({ story: entry });
});

/* ---------------- Ask a Question ---------------- */
// Instant answers for common questions are computed client-side straight from the
// app's own already-vetted state data (see ASK_TOPICS in index.html) — nothing here
// invents a legal fact. This is only for the fallback: a free-text question that
// didn't match one of those topics, which Antonio answers personally.
app.post('/api/questions', submitLimiter, optionalAuth, (req, res) => {
  const { question, state, contactEmail, website } = req.body || {};
  if(website) return res.json({ ok: true }); // honeypot field — bots fill it, real users never see it

  const questionText = String(question || '').trim();
  if(questionText.length < 10 || questionText.length > 500){
    return res.status(400).json({ error: 'Ask your question in 10–500 characters.' });
  }
  const stateAbbr = /^[A-Za-z]{2}$/.test(String(state || '')) ? String(state).toUpperCase() : null;
  const email = String(contactEmail || '').trim().slice(0, 200);
  const isPriority = !!(req.user && req.user.isMember); // member perk: jumps the queue — see /api/admin/questions sort

  const db = loadDB();
  db.questions.push({
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
    question: questionText,
    state: stateAbbr,
    contactEmail: email || null,
    status: 'pending',
    priority: isPriority,
    answer: null,
    createdAt: new Date().toISOString(),
    answeredAt: null,
  });
  if(db.questions.length > 2000) db.questions = db.questions.slice(-2000); // keep the file from growing forever
  saveDB(db);
  res.json({ ok: true });
});

app.get('/api/questions', (req, res) => {
  const db = loadDB();
  const answered = db.questions
    .filter(q => q.status === 'answered')
    .slice().reverse().slice(0, 200)
    .map(q => ({ id: q.id, state: q.state, question: q.question, answer: q.answer, createdAt: q.createdAt, answeredAt: q.answeredAt }));
  res.json({ questions: answered });
});

app.get('/api/admin/questions', authMiddleware, adminMiddleware, (req, res) => {
  const db = loadDB();
  // Member perk: pending questions from members ("priority") sort to the top, newest
  // first; everything else follows in its normal newest-first order underneath.
  const sorted = db.questions.slice().reverse().sort((a, b) => {
    const aTop = a.status === 'pending' && a.priority ? 1 : 0;
    const bTop = b.status === 'pending' && b.priority ? 1 : 0;
    return bTop - aTop;
  });
  res.json({ questions: sorted });
});

app.post('/api/admin/questions/:id/answer', authMiddleware, adminMiddleware, (req, res) => {
  const { answer } = req.body || {};
  const answerText = String(answer || '').trim();
  if(answerText.length < 3 || answerText.length > 3000){
    return res.status(400).json({ error: 'Answer must be 3–3000 characters.' });
  }
  const db = loadDB();
  const entry = db.questions.find(q => q.id === req.params.id);
  if(!entry) return res.status(404).json({ error: 'Question not found.' });
  entry.answer = answerText;
  entry.status = 'answered';
  entry.answeredAt = new Date().toISOString();
  saveDB(db);
  res.json({ question: entry });
});

app.post('/api/admin/questions/:id/status', authMiddleware, adminMiddleware, (req, res) => {
  const { status } = req.body || {};
  if(!['pending', 'answered', 'rejected'].includes(status)){
    return res.status(400).json({ error: 'status must be pending, answered, or rejected.' });
  }
  const db = loadDB();
  const entry = db.questions.find(q => q.id === req.params.id);
  if(!entry) return res.status(404).json({ error: 'Question not found.' });
  entry.status = status;
  saveDB(db);
  res.json({ question: entry });
});

/* ---------------- Advertise with us (local business inquiries) ---------------- */
// A lead-capture form, not a self-serve ad system — inquiries land in an admin-only
// inbox for Antonio to follow up with personally. Nothing here displays publicly.
app.post('/api/ad-inquiries', submitLimiter, (req, res) => {
  const { businessName, contact, website, message, website2 } = req.body || {};
  if(website2) return res.json({ ok: true }); // honeypot field — bots fill it, real users never see it

  const name = String(businessName || '').trim().slice(0, 120);
  const contactInfo = String(contact || '').trim().slice(0, 200);
  const messageText = String(message || '').trim();
  if(!name || !contactInfo){
    return res.status(400).json({ error: 'Business name and a way to reach you are both required.' });
  }
  if(messageText.length < 10 || messageText.length > 500){
    return res.status(400).json({ error: 'Tell us what you\'re interested in, in 10–500 characters.' });
  }
  const site = String(website || '').trim().slice(0, 300);

  const db = loadDB();
  db.adInquiries.push({
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
    businessName: name,
    contact: contactInfo,
    website: site || null,
    message: messageText,
    status: 'pending',
    createdAt: new Date().toISOString(),
  });
  if(db.adInquiries.length > 2000) db.adInquiries = db.adInquiries.slice(-2000);
  saveDB(db);
  res.json({ ok: true });
});

app.get('/api/admin/ad-inquiries', authMiddleware, adminMiddleware, (req, res) => {
  const db = loadDB();
  res.json({ inquiries: db.adInquiries.slice().reverse() });
});

app.post('/api/admin/ad-inquiries/:id/status', authMiddleware, adminMiddleware, (req, res) => {
  const { status } = req.body || {};
  if(!['pending', 'contacted', 'closed'].includes(status)){
    return res.status(400).json({ error: 'status must be pending, contacted, or closed.' });
  }
  const db = loadDB();
  const entry = db.adInquiries.find(a => a.id === req.params.id);
  if(!entry) return res.status(404).json({ error: 'Inquiry not found.' });
  entry.status = status;
  saveDB(db);
  res.json({ inquiry: entry });
});

/* ---------------- App feedback (admin-moderated inbox) ---------------- */
// General "tell us what you think" feedback — bugs, feature requests, praise, whatever.
// Anyone can submit, no account needed. Nothing here is ever shown publicly; it's an
// admin-only inbox, same shape as the ad-inquiries one above.
app.post('/api/feedback', submitLimiter, (req, res) => {
  const { category, message, contactEmail, website } = req.body || {};
  if(website) return res.json({ ok: true }); // honeypot field — bots fill it, real users never see it

  const validCategories = ['bug', 'feature idea', 'praise', 'other'];
  const cat = validCategories.includes(category) ? category : 'other';
  const messageText = String(message || '').trim();
  if(messageText.length < 5 || messageText.length > 1000){
    return res.status(400).json({ error: 'Tell us what\'s on your mind in 5–1000 characters.' });
  }
  const email = String(contactEmail || '').trim().slice(0, 200);

  const db = loadDB();
  db.feedback.push({
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
    category: cat,
    message: messageText,
    contactEmail: email || null,
    status: 'new',
    createdAt: new Date().toISOString(),
  });
  if(db.feedback.length > 2000) db.feedback = db.feedback.slice(-2000);
  saveDB(db);
  res.json({ ok: true });
});

app.get('/api/admin/feedback', authMiddleware, adminMiddleware, (req, res) => {
  const db = loadDB();
  res.json({ feedback: db.feedback.slice().reverse() });
});

app.post('/api/admin/feedback/:id/status', authMiddleware, adminMiddleware, (req, res) => {
  const { status } = req.body || {};
  if(!['new', 'read', 'resolved'].includes(status)){
    return res.status(400).json({ error: 'status must be new, read, or resolved.' });
  }
  const db = loadDB();
  const entry = db.feedback.find(f => f.id === req.params.id);
  if(!entry) return res.status(404).json({ error: 'Feedback not found.' });
  entry.status = status;
  saveDB(db);
  res.json({ feedback: entry });
});

/* ---------------- Community photos (link-based, admin-moderated) ---------------- */
// Same "paste a link to something already hosted" pattern as the pulled-over stories'
// video link — no file upload, no hosting account needed on our end. Admin-approved
// before anything shows up on the public Community tab.
app.post('/api/photos', submitLimiter, (req, res) => {
  const { photoLink, caption, state, displayName, website } = req.body || {};
  if(website) return res.json({ ok: true }); // honeypot field

  const link = String(photoLink || '').trim().slice(0, 500);
  if(!link || !isHttpUrl(link)){
    return res.status(400).json({ error: 'Paste a real link (starting with http:// or https://) to a photo you\'ve already uploaded somewhere.' });
  }
  const captionText = String(caption || '').trim().slice(0, 200);
  const stateAbbr = /^[A-Za-z]{2}$/.test(String(state || '')) ? String(state).toUpperCase() : null;
  const name = String(displayName || '').trim().slice(0, 40) || 'Anonymous';

  const db = loadDB();
  db.photos.push({
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
    photoLink: link,
    caption: captionText,
    state: stateAbbr,
    displayName: name,
    status: 'pending',
    createdAt: new Date().toISOString(),
  });
  if(db.photos.length > 2000) db.photos = db.photos.slice(-2000);
  saveDB(db);
  res.json({ ok: true });
});

app.get('/api/photos', (req, res) => {
  const db = loadDB();
  const approved = db.photos
    .filter(p => p.status === 'approved')
    .slice().reverse().slice(0, 200)
    .map(p => ({ id: p.id, photoLink: p.photoLink, caption: p.caption, state: p.state, displayName: p.displayName, createdAt: p.createdAt }));
  res.json({ photos: approved });
});

app.get('/api/admin/photos', authMiddleware, adminMiddleware, (req, res) => {
  const db = loadDB();
  res.json({ photos: db.photos.slice().reverse() });
});

app.post('/api/admin/photos/:id/status', authMiddleware, adminMiddleware, (req, res) => {
  const { status } = req.body || {};
  if(!['pending', 'approved', 'rejected'].includes(status)){
    return res.status(400).json({ error: 'status must be pending, approved, or rejected.' });
  }
  const db = loadDB();
  const entry = db.photos.find(p => p.id === req.params.id);
  if(!entry) return res.status(404).json({ error: 'Photo not found.' });
  entry.status = status;
  saveDB(db);
  res.json({ photo: entry });
});

/* ---------------- Traffic: visits, live count, admin dashboard ---------------- */
// visitorId is a random ID the app generates once per device and stores locally
// (not personal info, just a way to tell "one more open" from "one more person").
app.post('/api/visit', (req, res) => {
  const { visitorId } = req.body || {};
  const id = String(visitorId || '').slice(0, 100);
  const db = loadDB();
  db.visits.total += 1;
  if(id && !db.visits.uniqueIds.includes(id)){
    db.visits.uniqueIds.push(id);
    if(db.visits.uniqueIds.length > 100000) db.visits.uniqueIds = db.visits.uniqueIds.slice(-100000);
  }
  bumpDaily(db, 'visits', 1);
  saveDB(db);
  if(id) liveVisitors.set(id, Date.now());
  res.json({ ok: true });
});

app.post('/api/heartbeat', (req, res) => {
  const { visitorId } = req.body || {};
  const id = String(visitorId || '').slice(0, 100);
  if(id) liveVisitors.set(id, Date.now());
  res.json({ ok: true }); // no disk write here on purpose — this fires every ~20s per open tab
});

// Fire-and-forget: the app calls this whenever someone opens a state's page. No auth,
// no personal data — just "this state got looked at one more time," so Antonio can see
// which states actually get used. Silently ignores anything that isn't a real 2-letter code.
app.post('/api/state-view', (req, res) => {
  const abbr = String((req.body || {}).abbr || '').toUpperCase();
  if(/^[A-Z]{2}$/.test(abbr)){
    const db = loadDB();
    db.stateViews[abbr] = (db.stateViews[abbr] || 0) + 1;
    saveDB(db);
  }
  res.json({ ok: true });
});

// Fire-and-forget: which tab someone opened, so Antonio can see what actually gets used
// versus what's just sitting there. No auth, no personal data.
app.post('/api/tab-view', (req, res) => {
  const tab = String((req.body || {}).tab || '').toLowerCase().replace(/[^a-z0-9_-]/g, '').slice(0, 40);
  if(tab){
    const db = loadDB();
    db.tabViews[tab] = (db.tabViews[tab] || 0) + 1;
    saveDB(db);
  }
  res.json({ ok: true });
});

app.get('/api/admin/stats', authMiddleware, adminMiddleware, (req, res) => {
  const db = loadDB();
  const topStates = Object.entries(db.stateViews)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([abbr, count]) => ({ abbr, count }));
  const topTabs = Object.entries(db.tabViews)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([tab, count]) => ({ tab, count }));
  const quizTotals = Object.values(db.streaks).reduce((acc, s) => {
    acc.answered += s.totalAnswered || 0;
    acc.correct += s.totalCorrect || 0;
    return acc;
  }, { answered: 0, correct: 0 });
  const now = Date.now();
  const DAY = 24 * 60 * 60 * 1000;
  const signupsLast7Days = db.users.filter(u => now - new Date(u.createdAt).getTime() < 7 * DAY).length;
  const signupsLast30Days = db.users.filter(u => now - new Date(u.createdAt).getTime() < 30 * DAY).length;

  // Day-by-day series for the admin Dashboard graphs (added 2026-09-21), oldest first, today last.
  // Signups are derived fresh from each user's createdAt every time (works retroactively, can't drift);
  // visits/quiz activity come from the dailyStats bucket bumpDaily() has been filling in since this
  // shipped — days before that simply read as 0, not an error.
  const dailySeries = [];
  for(let i = 29; i >= 0; i--){
    const dateKey = new Date(now - i * DAY).toISOString().slice(0, 10);
    const daySignups = db.users.filter(u => String(u.createdAt || '').slice(0, 10) === dateKey).length;
    const bucket = db.dailyStats[dateKey] || {};
    dailySeries.push({
      date: dateKey,
      signups: daySignups,
      visits: bucket.visits || 0,
      quizAnswers: bucket.quizAnswers || 0,
      quizCorrect: bucket.quizCorrect || 0,
    });
  }

  res.json({
    totalUsers: db.users.length,
    totalVisits: db.visits.total,
    uniqueVisitors: db.visits.uniqueIds.length,
    liveNow: countLiveVisitors(),
    pendingStories: db.stories.filter(s => s.status === 'pending').length,
    pendingQuestions: db.questions.filter(q => q.status === 'pending').length,
    pendingAdInquiries: db.adInquiries.filter(a => a.status === 'pending').length,
    newFeedback: db.feedback.filter(f => f.status === 'new').length,
    pendingPhotos: db.photos.filter(p => p.status === 'pending').length,
    memberCount: db.users.filter(u => u.isMember).length,
    signupsLast7Days,
    signupsLast30Days,
    quizAnswersTotal: quizTotals.answered,
    quizCorrectTotal: quizTotals.correct,
    topStates,
    topTabs,
    dailySeries,
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
initStorage().then(() => {
  app.listen(PORT, () => console.log(
    'Edison backend running on port ' + PORT +
    (supabase ? ' — storage: Supabase (persists across restarts)' : ' — storage: local file (WILL lose data on restart/redeploy — set SUPABASE_URL/SUPABASE_SERVICE_ROLE_KEY to fix)')
  ));
}).catch(err => {
  console.error('Failed to initialize storage on startup — refusing to start with no data loaded:', err);
  process.exit(1);
});
