# Edison Gun Law Tracker — backend

A small real backend: accounts with hashed passwords, signed login sessions
(JWT), a shared daily-streak leaderboard, and one admin-only route that only
*your* account (whichever email you set as `ADMIN_EMAIL`) can reach.

## What this is not

This is a genuinely simple backend — one JSON file as storage, no database
server, no email verification, no password reset flow. It's enough to make
"login" and "admin view" *real* instead of client-side theater. If this app
ever gets meaningful traffic, the first upgrade is swapping the JSON file for
a real database (Postgres via [Supabase](https://supabase.com) or
[Neon](https://neon.tech) both have generous free tiers and are a natural
next step) — everything else here stays the same.

## Run it locally first

```bash
npm install
cp .env.example .env
# edit .env: set JWT_SECRET to a random string, and ADMIN_EMAIL to your own email
npm start
```

It'll start on `http://localhost:3000`. Test it:

```bash
curl http://localhost:3000/api/health
# {"ok":true}
```

## Deploy it somewhere with a real URL

The app (the HTML file) needs this backend to have a public `https://` URL
to talk to. The easiest free option:

**Render.com**
1. Push this folder to a GitHub repo (just this `edison-backend` folder, or
   the whole project — either works).
2. On Render: **New → Web Service**, connect the repo.
3. Build command: `npm install` — Start command: `npm start`.
4. Under **Environment**, add `JWT_SECRET` and `ADMIN_EMAIL` (same as your
   `.env`, but never commit the real `.env` file to GitHub — `.env` should
   stay out of version control).
5. Deploy. Render gives you a URL like `https://your-app.onrender.com`.

Railway and Fly.io work the same way if you'd rather use one of those.

**One important catch on free tiers:** many free hosting tiers "sleep" the
server after inactivity and take a few seconds to wake back up on the next
request. Fine for a hobby project; worth knowing if the first request after
a while feels slow.

## Wire it up to the app

Once deployed, copy the URL and paste it into the `API_BASE` constant near
the bottom of the HTML file's script (search for `const API_BASE`). Until
that's filled in, the app's login screen will tell people it isn't connected
yet rather than pretending to work.

## Becoming the admin

Register a normal account through the app using the exact email you set as
`ADMIN_EMAIL`. That account automatically gets `isAdmin: true` and can call:

```
GET /api/admin/users
Authorization: Bearer <your login token>
```

which returns every registered user's email, display name, and streak.
Nobody else's account can reach that route — the server checks
`req.user.isAdmin` on every request, not just whether the admin panel button
is visible in the app.

## API summary

| Route | Method | Auth | Purpose |
|---|---|---|---|
| `/api/health` | GET | none | Uptime check |
| `/api/register` | POST | none | Create an account, returns a token |
| `/api/login` | POST | none | Returns a token |
| `/api/me` | GET | Bearer token | Returns the signed-in user |
| `/api/leaderboard` | GET | none | Public top-25 by streak |
| `/api/streak` | POST | Bearer token | Records today's daily-question result |
| `/api/admin/users` | GET | Bearer token, admin only | Full user list |
| `/api/stories` | POST | none | Submit a pulled-over story for review |
| `/api/stories` | GET | none | Public feed of approved stories |
| `/api/admin/stories` | GET | Bearer token, admin only | Full story list, any status |
| `/api/admin/stories/:id/status` | POST | Bearer token, admin only | Approve/reject a story |
| `/api/questions` | POST | none | Submit a question for Antonio to answer |
| `/api/questions` | GET | none | Public feed of answered questions |
| `/api/admin/questions` | GET | Bearer token, admin only | Full question list, any status |
| `/api/admin/questions/:id/answer` | POST | Bearer token, admin only | Post an answer (publishes it) |
| `/api/admin/questions/:id/status` | POST | Bearer token, admin only | Reject a question without answering |
| `/api/visit` | POST | none | Records one app open, and marks that device "live" |
| `/api/heartbeat` | POST | none | Refreshes a device's "live" status (called every ~20s while the app is open, no disk write) |
| `/api/admin/stats` | GET | Bearer token, admin only | Dashboard tab's numbers: total users, total visits, unique visitors, live-right-now count, pending stories, pending questions |

## A note on the traffic numbers

`totalVisits` and `uniqueVisitors` are stored in the same `data.json` file as everything else, so
they're only as durable as that file — see "What this is not" above. `liveNow` (who's on the app
*right now*) isn't stored on disk at all; it lives in memory and resets to 0 every time the server
restarts or redeploys. On Render's free tier specifically, the whole filesystem is ephemeral, so a
redeploy (or the free-tier sleep/wake cycle) can also wipe `data.json` itself, taking the visit
counts with it. None of this breaks anything — the app just starts counting again from zero — but
if Antonio ever wants these numbers to survive restarts, the fix is the same one already called out
above: move from the JSON file to a real database with a persistent disk (Postgres via Supabase or
Neon).
