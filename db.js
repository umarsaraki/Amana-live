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
ALTER TABLE Users ADD COLUMN IF NOT EXISTS agencyApplicationStatus TEXT DEFAULT 'none'; -- none | pending
ALTER TABLE Users ADD COLUMN IF NOT EXISTS agencyApplicationDbId TEXT;
ALTER TABLE Users ADD COLUMN IF NOT EXISTS gender TEXT;                     -- 'male' | 'female'
ALTER TABLE Users ADD COLUMN IF NOT EXISTS country TEXT;
ALTER TABLE Users ADD COLUMN IF NOT EXISTS countryChangesUsed INTEGER DEFAULT 0;
ALTER TABLE Users ADD COLUMN IF NOT EXISTS isHostBadge BOOLEAN DEFAULT FALSE;
ALTER TABLE Users ADD COLUMN IF NOT EXISTS isDbBadge BOOLEAN DEFAULT FALSE;
ALTER TABLE Users ADD COLUMN IF NOT EXISTS backgroundPics JSONB DEFAULT '[]'; -- up to 5 URLs
ALTER TABLE Users ADD COLUMN IF NOT EXISTS prettyId TEXT;
ALTER TABLE Users ADD COLUMN IF NOT EXISTS prettyIdExpiresAt TIMESTAMPTZ;
ALTER TABLE Users ADD COLUMN IF NOT EXISTS loginPinHash TEXT;
ALTER TABLE Users ADD COLUMN IF NOT EXISTS clearedMessagesAt TIMESTAMPTZ;
ALTER TABLE Users ADD COLUMN IF NOT EXISTS clearedLiveRecordAt TIMESTAMPTZ;

-- MESSAGE feature -----------------------------------------------------
CREATE TABLE IF NOT EXISTS Messages (
  id SERIAL PRIMARY KEY,
  senderId INTEGER NOT NULL REFERENCES Users(id),
  receiverId INTEGER NOT NULL REFERENCES Users(id),
  content TEXT,
  giftId INTEGER REFERENCES Gifts(id),
  createdAt TIMESTAMPTZ DEFAULT now(),
  readAt TIMESTAMPTZ,
  deletedForSender BOOLEAN DEFAULT FALSE,
  deletedForReceiver BOOLEAN DEFAULT FALSE,
  unreadFlag BOOLEAN DEFAULT FALSE
);
CREATE TABLE IF NOT EXISTS MessageReports (
  id SERIAL PRIMARY KEY,
  messageId INTEGER REFERENCES Messages(id),
  reportedBy INTEGER REFERENCES Users(id),
  reason TEXT,
  createdAt TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ProfileViews (
  id SERIAL PRIMARY KEY,
  viewerId INTEGER NOT NULL REFERENCES Users(id),
  viewedId INTEGER NOT NULL REFERENCES Users(id),
  createdAt TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS SquareMessages (
  id SERIAL PRIMARY KEY,
  userId INTEGER NOT NULL REFERENCES Users(id),
  country TEXT NOT NULL,
  content TEXT NOT NULL,
  createdAt TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS SystemMessages (
  id SERIAL PRIMARY KEY,
  userId INTEGER NOT NULL REFERENCES Users(id),
  type TEXT NOT NULL, -- task | recharge | withdraw
  content TEXT NOT NULL,
  createdAt TIMESTAMPTZ DEFAULT now(),
  readAt TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS OfficialMessages (
  id SERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  createdAt TIMESTAMPTZ DEFAULT now()
);

-- MOMENTS feature -------------------------------------------------------
CREATE TABLE IF NOT EXISTS Moments (
  id SERIAL PRIMARY KEY,
  userId INTEGER NOT NULL REFERENCES Users(id),
  text TEXT,
  images JSONB DEFAULT '[]', -- up to 9 image URLs
  createdAt TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS MomentLikes (
  momentId INTEGER NOT NULL REFERENCES Moments(id),
  userId INTEGER NOT NULL REFERENCES Users(id),
  createdAt TIMESTAMPTZ DEFAULT now(),
  PRIMARY KEY (momentId, userId)
);
CREATE TABLE IF NOT EXISTS MomentComments (
  id SERIAL PRIMARY KEY,
  momentId INTEGER NOT NULL REFERENCES Moments(id),
  userId INTEGER NOT NULL REFERENCES Users(id),
  content TEXT NOT NULL,
  createdAt TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS MomentSaves (
  momentId INTEGER NOT NULL REFERENCES Moments(id),
  userId INTEGER NOT NULL REFERENCES Users(id),
  createdAt TIMESTAMPTZ DEFAULT now(),
  PRIMARY KEY (momentId, userId)
);
CREATE TABLE IF NOT EXISTS MomentTags (
  momentId INTEGER NOT NULL REFERENCES Moments(id),
  userId INTEGER NOT NULL REFERENCES Users(id),
  PRIMARY KEY (momentId, userId)
);

ALTER TABLE Users ADD COLUMN IF NOT EXISTS selectedRoomCoverTier INTEGER;

-- LEVEL SYSTEM (Room / Send / Receive) - cosmetics only, never resets ------
CREATE TABLE IF NOT EXISTS RoomLevelTiers (
  tierStart INTEGER PRIMARY KEY, tierEnd INTEGER NOT NULL, threshold BIGINT NOT NULL,
  colorHex TEXT NOT NULL, name TEXT NOT NULL, effect TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS SendLevelTiers (
  tierStart INTEGER PRIMARY KEY, tierEnd INTEGER NOT NULL, threshold BIGINT NOT NULL,
  colorHex TEXT NOT NULL, name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ReceiveLevelTiers (
  tierStart INTEGER PRIMARY KEY, tierEnd INTEGER NOT NULL, threshold BIGINT NOT NULL,
  colorHex TEXT NOT NULL, name TEXT NOT NULL
);
INSERT INTO RoomLevelTiers (tierStart, tierEnd, threshold, colorHex, name, effect) VALUES
  (1,4,0,'#9CA3AF','Default Cover','None'),
  (5,9,1000000,'#22C55E','Green Garden Cover','Green Border'),
  (10,14,10000000,'#CD7F32','Bronze Castle Cover','Bronze Border + Confetti'),
  (15,19,50000000,'#C0C0C0','Silver Palace Cover','Silver Particles'),
  (20,24,100000000,'#FFD700','Gold Throne Cover','Gold Glow'),
  (25,29,300000000,'#22D3EE','Diamond Ocean Cover','Diamond Sparkles'),
  (30,34,500000000,'#800080','Crown Kingdom Cover','Purple Crown Lights'),
  (35,39,1000000000,'#DC143C','King Empire Cover','Red Fire Effect'),
  (40,44,3000000000,'#FF8C00','Emperor Dynasty Cover','Orange Fireworks'),
  (45,49,5000000000,'#FF69B4','Legend Star Cover','Pink Galaxy'),
  (50,54,10000000000,'#8B5CF6','Mythic Universe Cover','Violet Nebula'),
  (55,59,30000000000,'#FDE68A','God Heaven Cover','Gold White Sky'),
  (60,64,50000000000,'#4682B4','Titan World Cover','Steel Blue Storm'),
  (65,69,80000000000,'#111827','Conqueror War Cover','Black Gold War'),
  (70,74,100000000000,'#C4B5FD','Celestial Cloud Cover','Light Purple Clouds'),
  (75,79,300000000000,'#FFFFFF','Divine Light Cover','White Holy Light'),
  (80,84,500000000000,'#4A148C','Immortal Shadow Cover','Dark Purple Mist'),
  (85,89,1000000000000,'#FF5722','Eternal Flame Cover','Fire Orange Flames'),
  (90,94,5000000000000,'#3F51B5','Supreme Ocean Cover','Royal Blue Waves'),
  (95,99,10000000000000,'#EC4899','GOD Realm Cover','Rainbow Lightning'),
  (100,100,20000000000000,'linear-gradient(135deg,#F59E0B,#EC4899,#8B5CF6)','GOD MYTHIC Cover','Full Screen Rainbow + God Voice')
  ON CONFLICT (tierStart) DO NOTHING;
INSERT INTO SendLevelTiers (tierStart, tierEnd, threshold, colorHex, name) VALUES
  (1,4,0,'#808080','None'),
  (5,9,50000,'#4CAF50','None'),
  (10,14,3000000,'#CD7F32','Bronze Frame'),
  (15,19,8000000,'#C0C0C0','Silver Frame'),
  (20,24,16500000,'#FFD700','Gold Frame'),
  (25,29,30000000,'#ADD8E6','Platinum Frame'),
  (30,34,50000000,'#00FFFF','Diamond Frame'),
  (35,39,80000000,'#800080','Crown Frame'),
  (40,44,120000000,'#DC143C','King Frame'),
  (45,49,180000000,'#FF8C00','Emperor Frame'),
  (50,54,250000000,'#FF69B4','Legend Frame'),
  (55,59,350000000,'#9C27B0','Mythic Frame'),
  (60,64,500000000,'#FFD700','God Frame'),
  (65,69,700000000,'#607D8B','Titan Frame'),
  (70,74,1000000000,'#000000','Conqueror Frame'),
  (75,79,1500000000,'#E1BEE7','Celestial Frame'),
  (80,84,2000000000,'#FFFFFF','Divine Frame'),
  (85,89,3000000000,'#4A148C','Immortal Frame'),
  (90,94,5000000000,'#FF5722','Eternal Frame'),
  (95,99,10000000000,'#3F51B5','Supreme Frame'),
  (100,100,20000000000,'linear-gradient(135deg,#F59E0B,#EC4899,#8B5CF6)','GOD MYTHIC Frame')
  ON CONFLICT (tierStart) DO NOTHING;
INSERT INTO ReceiveLevelTiers (tierStart, tierEnd, threshold, colorHex, name) VALUES
  (1,4,0,'#808080','None'),
  (5,9,50000,'#4CAF50','None'),
  (10,14,3000000,'#CD7F32','Bronze Car'),
  (15,19,8000000,'#C0C0C0','Silver Motorcycle'),
  (20,24,16500000,'#FFD700','Gold Horse'),
  (25,29,30000000,'#ADD8E6','Platinum Jet Ski'),
  (30,34,50000000,'#00FFFF','Diamond Sports Car'),
  (35,39,80000000,'#800080','Crown Carriage'),
  (40,44,120000000,'#DC143C','Red Dragon'),
  (45,49,180000000,'#FF8C00','Emperor Chariot'),
  (50,54,250000000,'#FF69B4','Pink Phoenix'),
  (55,59,350000000,'#9C27B0','Mythic Unicorn'),
  (60,64,500000000,'#FFD700','God Thunder'),
  (65,69,700000000,'#607D8B','Titan Beast'),
  (70,74,1000000000,'#000000','Conqueror Ship'),
  (75,79,1500000000,'#E1BEE7','Celestial Angel'),
  (80,84,2000000000,'#FFFFFF','Divine Phoenix'),
  (85,89,3000000000,'#4A148C','Immortal Dragon'),
  (90,94,5000000000,'#FF5722','Eternal Galaxy'),
  (95,99,10000000000,'#3F51B5','Supreme Lion'),
  (100,100,20000000000,'linear-gradient(135deg,#F59E0B,#EC4899,#8B5CF6)','GOD HEAVEN Ride')
  ON CONFLICT (tierStart) DO NOTHING;

-- VIP SYSTEM --------------------------------------------------------------
ALTER TABLE Users ADD COLUMN IF NOT EXISTS vipLastClaimAt TIMESTAMPTZ;
CREATE TABLE IF NOT EXISTS VipLevels (
  level INTEGER PRIMARY KEY,
  title TEXT NOT NULL,
  spendRequired BIGINT NOT NULL,
  dailyClaimCoins INTEGER NOT NULL,
  badgeColor TEXT NOT NULL,
  purchaseDiscountPct INTEGER NOT NULL DEFAULT 0,
  exchangeUserPct INTEGER NOT NULL DEFAULT 70
);
INSERT INTO VipLevels (level, title, spendRequired, dailyClaimCoins, badgeColor, purchaseDiscountPct, exchangeUserPct) VALUES
  (1,  'Bronze Member',   100000,      2000,  '#CD7F32', 0,  70),
  (2,  'Silver Member',   500000,      3000,  '#C0C0C0', 0,  70),
  (3,  'Gold Member',     1000000,     5000,  '#FFD700', 5,  70),
  (4,  'Platinum',        3000000,     8000,  '#ADD8E6', 10, 70),
  (5,  'Diamond',         5000000,     10000, '#00C2D1', 10, 75),
  (6,  'Crown',           10000000,    15000, '#800080', 10, 75),
  (7,  'King',            20000000,    20000, '#DC143C', 15, 80),
  (8,  'Emperor',         50000000,    30000, '#FF8C00', 15, 80),
  (9,  'Legend',          100000000,   40000, '#FF69B4', 20, 80),
  (10, 'Mythic',          500000000,   50000, 'linear-gradient(135deg,#F59E0B,#EC4899,#8B5CF6)', 20, 100)
  ON CONFLICT (level) DO NOTHING;

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
ALTER TABLE Gifts ADD COLUMN IF NOT EXISTS minVipLevel INTEGER DEFAULT 0;

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
