# Amana Live

Just 7 files. No routes/ folder, no middleware/ folder, no socket/ folder,
no build step, no separate frontend files.

```
.
├── server.js          Everything backend: Express API, JWT auth, all
│                        routes (auth, wallet, gifts, referral, tasks,
│                        streams, follow, leaderboard), and Socket.io
│                        (WebRTC signaling, chat, gifts) - one file.
├── db.js               PostgreSQL connection + the full schema + seed
│                        data. Runs automatically when the server starts -
│                        no separate init step.
├── public/
│   └── index.html       The ENTIRE frontend - one file. HTML, CSS (inline
│                         <style>), and JS (inline <script>). Talks to the
│                         real API with fetch() and to Socket.io for live
│                         features.
├── package.json
├── .env.example
├── .gitignore
└── README.md
```

- **Backend + Frontend host:** Node.js + Express + Socket.io
- **Frontend:** one plain HTML file, no framework, no build
- **Database:** PostgreSQL - schema + seed data created automatically on startup
- **Auth:** Email + Password + Phone OTP. No Google Sign-In.

## Running it

You need a PostgreSQL database - either install it locally or use a free
one from your hosting provider.

```bash
npm install
cp .env.example .env      # fill in DATABASE_URL and JWT_SECRET
npm start
```

Open **http://localhost:5000**. Tables and seed data (gift catalog, demo
agencies) are created automatically the first time the server starts -
nothing else to run.

**Login/Register are intentionally not in the frontend yet** — the whole
app is being built out first. On first load, the app silently signs in as
one shared "working" account (a real row in the real `Users` table - it
registers itself automatically the very first time, then just logs in on
every visit after that). Every screen works against real data through this
one account while the rest of the app gets built.

The real Login/Register screens (and the account-switching that implies)
go back into the frontend once everything else is finished - the backend
endpoints (`/api/auth/register`, `/api/auth/login`, phone OTP) are already
fully built and untouched, only the frontend UI for them is deferred.

## Deploying (e.g. Render, Railway)

1. Push this repo to GitHub.
2. Create a PostgreSQL database on your host and copy its connection string.
3. Create a new **Web Service** from this repo:
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
4. Set environment variables: `DATABASE_URL`, `JWT_SECRET` (see `.env.example`).
5. Deploy. The database tables are created automatically on first boot.
6. Create your first account with the `curl` command above (using your live URL instead of localhost), then log in from the site.

## Features

- **Home v3** — Live tab (banner slider, Agency/Gift Wall/Room Wall buttons linking to leaderboards, filter tags computed from real host/room data, live list) and Follow tab (top stories with long-press pin, rooms you manage, followed rooms).
- **Go Live (Audio)** — real WebRTC audio broadcast via the browser's mic, signaled through Socket.io. No camera/video yet.
- **Gifts** — coin-based gifting with a 50/50 commission split (sender pays coins, host earns 50% as withdrawable diamonds).
- **Referral** — every user gets a unique AmanaID; referring someone earns a coin bonus.
- **7-Day Tasks** — a 7-day onboarding task ladder, one task unlocked per day.
- **Leaderboard** — Daily/Weekly/Monthly rankings for Agency, Gift Wall, Room Wall, and Host, computed live from the transactions table.

## Known gaps / next steps

- **Login/Register screens** — deferred on purpose, see above. The app currently runs as one shared working account.
- **Seats in the Audio Live room** — tapping a seat is currently visual-only on your own screen; there's no seats table/socket event yet to sync who's sitting where across everyone in the room.
- **Agencies** — the table exists and the Agency Leaderboard reads from it, but there's no admin UI yet to assign a host to an agency - do it directly in the database for now.
- **Language switching** — the globe menu remembers your choice but doesn't yet translate all on-screen text.
- **Moment / Game / Message** tabs are placeholder screens - no spec provided yet.
- 
