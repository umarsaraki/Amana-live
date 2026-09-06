// db.js
// PostgreSQL connection pool + the full database schema + seed data, all in
// one file. There is no separate "npm run db:init" step - initDb() runs
// automatically every time the server starts (server.js calls it once
// before listening). Every CREATE TABLE uses IF NOT EXISTS, so this is safe
// to run on every restart/deploy without wiping existing data.

import pg from "pg";
import dotenv from "dotenv";

dotenv.config();

const { Pool } = pg;

// Render's PostgreSQL requires SSL on the External Database URL (and it's
// harmless to also allow it on the Internal URL, which doesn't insist on
// it). `rejectUnauthorized: false` is what Render's own docs recommend,
// since their internal certs aren't in Node's public CA list.
const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
    })
  : new Pool({
      host: process.env.PGHOST || "localhost",
      port: Number(process.env.PGPORT) || 5432,
      user: process.env.PGUSER || "postgres",
      password: process.env.PGPASSWORD || "postgres",
      database: process.env.PGDATABASE || "amana_live",
    });

pool.on("error", (err) => {
  console.error("Unexpected PostgreSQL pool error:", err);
});

// Small helper so the rest of the app can do: `const { rows } = await query("SELECT ...", [params])`
export async function query(text, params) {
  return pool.query(text, params);
}

// ===================================================================
// SCHEMA - every table the app uses
// ===================================================================
const SCHEMA_SQL = `
-- USERS ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS Users (
  id SERIAL PRIMARY KEY,
  amanaId TEXT UNIQUE NOT NULL,          -- public referral / handle id e.g. AMN-XXXXXX
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  passwordHash TEXT NOT NULL,
  phone TEXT UNIQUE,
  phoneVerified BOOLEAN DEFAULT FALSE,
  avatar TEXT DEFAULT '',
  bio TEXT DEFAULT '',
  referredBy TEXT,
  agencyId INTEGER,
  createdAt TIMESTAMPTZ DEFAULT now(),
  lastLoginAt TIMESTAMPTZ
);

-- PHONE OTP --------------------------------------------------------------
CREATE TABLE IF NOT EXISTS PhoneOtps (
  id SERIAL PRIMARY KEY,
  phone TEXT NOT NULL,
  code TEXT NOT NULL,
  expiresAt TIMESTAMPTZ NOT NULL,
  consumed BOOLEAN DEFAULT FALSE,
  createdAt TIMESTAMPTZ DEFAULT now()
);

-- AGENCIES (hosts can belong to one; powers the Agency Leaderboard) -------
CREATE TABLE IF NOT EXISTS Agencies (
  id SERIAL PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  createdAt TIMESTAMPTZ DEFAULT now()
);
ALTER TABLE Users ADD COLUMN IF NOT EXISTS agencyId INTEGER REFERENCES Agencies(id);

-- LIVE STREAMS -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS LiveStreams (
  id SERIAL PRIMARY KEY,
  streamKey TEXT UNIQUE NOT NULL,
  hostId INTEGER NOT NULL REFERENCES Users(id),
  title TEXT DEFAULT 'Live',
  status TEXT DEFAULT 'live',            -- live | ended
  roomType TEXT DEFAULT 'stage',         -- stage | video | pk (Party is derived, not stored)
  viewerCount INTEGER DEFAULT 0,
  peakViewers INTEGER DEFAULT 0,
  totalCoinsEarned INTEGER DEFAULT 0,
  startedAt TIMESTAMPTZ DEFAULT now(),
  endedAt TIMESTAMPTZ
);

-- GIFT CATALOG --------------------------------------------------------------
CREATE TABLE IF NOT EXISTS Gifts (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  icon TEXT NOT NULL,
  coinCost INTEGER NOT NULL
);

-- TRANSACTIONS (every coin movement) ----------------------------------------
CREATE TABLE IF NOT EXISTS Transactions (
  id SERIAL PRIMARY KEY,
  userId INTEGER NOT NULL REFERENCES Users(id),
  type TEXT NOT NULL,                    -- purchase | gift_sent | gift_received | task_reward | referral_bonus | withdrawal
  amount INTEGER NOT NULL,
  meta JSONB,
  createdAt TIMESTAMPTZ DEFAULT now()
);

-- REFERRALS -------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS Referrals (
  id SERIAL PRIMARY KEY,
  referrerId INTEGER NOT NULL REFERENCES Users(id),
  referredId INTEGER NOT NULL REFERENCES Users(id),
  bonusCoins INTEGER DEFAULT 100,
  createdAt TIMESTAMPTZ DEFAULT now()
);

-- USER TASKS (7-day onboarding ladder) -----------------------------------------
CREATE TABLE IF NOT EXISTS UserTask (
  id SERIAL PRIMARY KEY,
  userId INTEGER NOT NULL REFERENCES Users(id),
  day INTEGER NOT NULL,
  title TEXT NOT NULL,
  rewardCoins INTEGER NOT NULL,
  completed BOOLEAN DEFAULT FALSE,
  completedAt TIMESTAMPTZ,
  UNIQUE(userId, day)
);

-- WALLETS ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS Wallets (
  userId INTEGER PRIMARY KEY REFERENCES Users(id),
  coinBalance INTEGER DEFAULT 0,
  diamondBalance INTEGER DEFAULT 0,
  updatedAt TIMESTAMPTZ DEFAULT now()
);

-- CHAT MESSAGES -----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ChatMessages (
  id SERIAL PRIMARY KEY,
  streamId INTEGER NOT NULL REFERENCES LiveStreams(id),
  userId INTEGER REFERENCES Users(id),
  username TEXT NOT NULL,
  message TEXT NOT NULL,
  createdAt TIMESTAMPTZ DEFAULT now()
);

-- FOLLOWS (Follow tab: top stories, followed rooms) ------------------------------
CREATE TABLE IF NOT EXISTS Follows (
  id SERIAL PRIMARY KEY,
  followerId INTEGER NOT NULL REFERENCES Users(id),
  followedId INTEGER NOT NULL REFERENCES Users(id),
  pinned BOOLEAN DEFAULT FALSE,
  createdAt TIMESTAMPTZ DEFAULT now(),
  UNIQUE(followerId, followedId)
);

-- ROOM ADMINS (co-managers of a room, beyond the single host) --------------------
CREATE TABLE IF NOT EXISTS RoomAdmins (
  id SERIAL PRIMARY KEY,
  streamId INTEGER NOT NULL REFERENCES LiveStreams(id),
  userId INTEGER NOT NULL REFERENCES Users(id),
  createdAt TIMESTAMPTZ DEFAULT now(),
  UNIQUE(streamId, userId)
);

-- Indexes for a multi-user, concurrent-write workload
CREATE INDEX IF NOT EXISTS idx_transactions_userid ON Transactions(userId);
CREATE INDEX IF NOT EXISTS idx_livestreams_status ON LiveStreams(status);
CREATE INDEX IF NOT EXISTS idx_chatmessages_streamid ON ChatMessages(streamId);
CREATE INDEX IF NOT EXISTS idx_usertask_userid ON UserTask(userId);
CREATE INDEX IF NOT EXISTS idx_follows_follower ON Follows(followerId);
CREATE INDEX IF NOT EXISTS idx_follows_followed ON Follows(followedId);
`;

const DEFAULT_GIFTS = [
  ["Rose", "🌹", 10],
  ["Heart", "❤️", 20],
  ["Star", "⭐", 50],
  ["Crown", "👑", 200],
  ["Diamond", "💎", 500],
  ["Rocket", "🚀", 1000],
];
const DEFAULT_AGENCIES = ["Royal Empire", "Star Agency", "Elite Voices", "Desert Kings", "Sahara Stars"];

// Creates all tables (if missing) and seeds the gift catalog / demo agencies
// (if empty). Safe to call on every server start - nothing is duplicated or
// overwritten on repeat runs.
export async function initDb() {
  await pool.query(SCHEMA_SQL);

  const giftCount = await pool.query("SELECT COUNT(*)::int AS c FROM Gifts");
  if (giftCount.rows[0].c === 0) {
    for (const [name, icon, coinCost] of DEFAULT_GIFTS) {
      await pool.query("INSERT INTO Gifts (name, icon, coinCost) VALUES ($1, $2, $3)", [name, icon, coinCost]);
    }
  }

  const agencyCount = await pool.query("SELECT COUNT(*)::int AS c FROM Agencies");
  if (agencyCount.rows[0].c === 0) {
    for (const name of DEFAULT_AGENCIES) {
      await pool.query("INSERT INTO Agencies (name) VALUES ($1) ON CONFLICT (name) DO NOTHING", [name]);
    }
  }

  console.log("✅ Database schema ready (tables created if missing, gifts/agencies seeded if empty)");
}

export default pool;
