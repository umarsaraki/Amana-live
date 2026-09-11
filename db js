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
-- STORE + DRESS UP ----------------------------------------------------------
CREATE TABLE IF NOT EXISTS AppSettings (
  key TEXT PRIMARY KEY,
  value JSONB NOT NULL
);
INSERT INTO AppSettings (key, value) VALUES ('store_enabled', 'true'), ('dressup_enabled', 'true') ON CONFLICT (key) DO NOTHING;

CREATE TABLE IF NOT EXISTS StoreItems (
  id SERIAL PRIMARY KEY,
  category TEXT NOT NULL, -- frame | ride | roomcover
  name TEXT NOT NULL,
  price INTEGER NOT NULL,
  effect TEXT,
  durationDays INTEGER NOT NULL DEFAULT 30,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  saleDiscountPct INTEGER NOT NULL DEFAULT 0,
  saleEndsAt TIMESTAMPTZ
);
INSERT INTO StoreItems (category, name, price, effect) VALUES
  ('frame','Pink Angel',99999,'Pink wings + hearts'),
  ('frame','Gold Dragon',199999,'Gold dragon'),
  ('frame','Diamond Queen',299999,'Diamond shine'),
  ('frame','Ice Crystal',399999,'Ice particles'),
  ('frame','Fire Phoenix',499999,'Fire wings'),
  ('frame','Galaxy Star',699999,'Galaxy moving'),
  ('frame','Royal Crown',999999,'Royal crown'),
  ('frame','Ocean King',1499999,'Water waves'),
  ('frame','Thunder God',1999999,'Lightning'),
  ('frame','GOD HEAVEN',4999999,'Rainbow GOD ring'),
  ('ride','Love Bike',199999,'Pink bike'),
  ('ride','Royal Carriage',399999,'Gold carriage'),
  ('ride','Sports Car',599999,'Red car'),
  ('ride','Magic Carpet',799999,'Flying carpet'),
  ('ride','Crystal Boat',999999,'Crystal boat'),
  ('ride','Dragon Mount',1299999,'Flying dragon'),
  ('ride','Golden Ship',1699999,'Golden ship'),
  ('ride','Unicorn',2199999,'Rainbow unicorn'),
  ('ride','Space Rocket',2999999,'Rocket'),
  ('ride','GOD HEAVEN RIDE',6999999,'Rainbow GOD cloud'),
  ('roomcover','Cherry Garden',99999,'Cherry blossoms'),
  ('roomcover','Night City',199999,'City lights'),
  ('roomcover','Beach Sunset',299999,'Beach'),
  ('roomcover','Snow Castle',399999,'Snow castle'),
  ('roomcover','Forest Fairy',499999,'Forest'),
  ('roomcover','Golden Palace',699999,'Gold palace'),
  ('roomcover','Underwater',899999,'Ocean'),
  ('roomcover','Space Galaxy',1199999,'Planets'),
  ('roomcover','Diamond Hall',1599999,'Diamond room'),
  ('roomcover','GOD HEAVEN ISLAND',3999999,'GOD island')
  ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS UserInventory (
  id SERIAL PRIMARY KEY,
  userId INTEGER NOT NULL REFERENCES Users(id),
  itemId INTEGER NOT NULL REFERENCES StoreItems(id),
  purchasedAt TIMESTAMPTZ DEFAULT now(),
  expiresAt TIMESTAMPTZ NOT NULL,
  equipped BOOLEAN NOT NULL DEFAULT FALSE,
  notifiedExpirySoon BOOLEAN NOT NULL DEFAULT FALSE,
  UNIQUE (userId, itemId)
);

-- VERIFY CENTER (DB / Agency / Host hierarchy) -----------------------------
ALTER TABLE Users ADD COLUMN IF NOT EXISTS verifiedType TEXT DEFAULT 'none'; -- none | db | agency | host
ALTER TABLE Users ADD COLUMN IF NOT EXISTS dbCode TEXT UNIQUE; -- own DB code, only set if verifiedType = 'db'
ALTER TABLE Users ADD COLUMN IF NOT EXISTS supervisingDbId TEXT; -- for agency/host: the DB code overseeing them
ALTER TABLE Users ADD COLUMN IF NOT EXISTS verificationRejectionReason TEXT;
ALTER TABLE Users ADD COLUMN IF NOT EXISTS isBanned BOOLEAN DEFAULT FALSE;
ALTER TABLE Agencies ADD COLUMN IF NOT EXISTS ownerUserId INTEGER REFERENCES Users(id);
ALTER TABLE Agencies ADD COLUMN IF NOT EXISTS agencyCode TEXT UNIQUE;
ALTER TABLE Agencies ADD COLUMN IF NOT EXISTS dbId TEXT; -- supervising DB code
ALTER TABLE Agencies ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE Agencies ADD COLUMN IF NOT EXISTS logoUrl TEXT;
ALTER TABLE Agencies ADD COLUMN IF NOT EXISTS monthlyUserGoal INTEGER;
ALTER TABLE Agencies ADD COLUMN IF NOT EXISTS fullName TEXT;
ALTER TABLE Agencies ADD COLUMN IF NOT EXISTS phone TEXT;
ALTER TABLE Agencies ADD COLUMN IF NOT EXISTS country TEXT;
ALTER TABLE Agencies ADD COLUMN IF NOT EXISTS email TEXT;
CREATE TABLE IF NOT EXISTS VerificationRequests (
  id SERIAL PRIMARY KEY,
  userId INTEGER NOT NULL REFERENCES Users(id),
  type TEXT NOT NULL, -- db | agency | host
  fields JSONB NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending', -- pending | approved | rejected
  rejectionReason TEXT,
  resolvedBy INTEGER REFERENCES Users(id),
  createdAt TIMESTAMPTZ DEFAULT now(),
  resolvedAt TIMESTAMPTZ
);

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

-- RESELLER PANEL -----------------------------------------------------------
-- Reseller status is NOT a DB flag - it's determined by matching the user's
-- email against the RESELLER_EMAILS environment variable (see server.js).
CREATE TABLE IF NOT EXISTS ResellerDeals (
  id SERIAL PRIMARY KEY,
  dealType TEXT NOT NULL, -- sell_diamonds_to_company | buy_coins_from_company | buy_diamonds_from_user | sell_coins_to_user
  resellerId INTEGER NOT NULL REFERENCES Users(id),
  counterpartyUserId INTEGER REFERENCES Users(id), -- NULL for company deals
  initiatedBy INTEGER REFERENCES Users(id),
  assetType TEXT NOT NULL, -- coins | diamonds
  amount BIGINT NOT NULL,
  usdAmount NUMERIC,
  payoutInfo JSONB,
  status TEXT NOT NULL DEFAULT 'pending', -- pending | approved | rejected
  createdAt TIMESTAMPTZ DEFAULT now(),
  resolvedAt TIMESTAMPTZ
);

-- FAMILY SYSTEM ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS Families (
  id SERIAL PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  headUserId INTEGER NOT NULL REFERENCES Users(id),
  totalCoins BIGINT NOT NULL DEFAULT 0,
  selectedCoverTier INTEGER,
  createdAt TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS FamilyMembers (
  familyId INTEGER NOT NULL REFERENCES Families(id),
  userId INTEGER NOT NULL UNIQUE REFERENCES Users(id),
  role TEXT NOT NULL DEFAULT 'member', -- head | admin | member
  contributedCoins BIGINT NOT NULL DEFAULT 0,
  joinedAt TIMESTAMPTZ DEFAULT now(),
  PRIMARY KEY (familyId, userId)
);
CREATE TABLE IF NOT EXISTS FamilyApplications (
  id SERIAL PRIMARY KEY,
  familyId INTEGER NOT NULL REFERENCES Families(id),
  userId INTEGER NOT NULL REFERENCES Users(id),
  status TEXT NOT NULL DEFAULT 'pending', -- pending | accepted | rejected
  createdAt TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS FamilyMessages (
  id SERIAL PRIMARY KEY,
  familyId INTEGER NOT NULL REFERENCES Families(id),
  userId INTEGER REFERENCES Users(id), -- NULL = system message
  content TEXT NOT NULL,
  giftId INTEGER REFERENCES Gifts(id),
  isSystem BOOLEAN DEFAULT FALSE,
  createdAt TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS FamilyLevelTiers (
  tierStart INTEGER PRIMARY KEY, tierEnd INTEGER NOT NULL, threshold BIGINT NOT NULL,
  title TEXT NOT NULL, badgeName TEXT NOT NULL, coverName TEXT NOT NULL
);
INSERT INTO FamilyLevelTiers (tierStart, tierEnd, threshold, title, badgeName, coverName) VALUES
  (1,4,0,'New Family','Bronze Badge','Default'),
  (5,9,10000000,'Rising Family','Silver Badge','Green Garden'),
  (10,14,50000000,'Elite Family','Gold Badge','Bronze Castle'),
  (15,19,200000000,'Noble Family','Platinum Badge','Silver Palace'),
  (20,24,500000000,'Royal Family','Diamond Badge','Gold Throne'),
  (25,29,1000000000,'Crown Family','Crown Badge','Diamond Ocean'),
  (30,34,3000000000,'King Family','King Badge','Crown Kingdom'),
  (35,39,5000000000,'Emperor Family','Emperor Badge','King Empire'),
  (40,44,10000000000,'Legend Family','Legend Badge','Legend Star'),
  (45,49,20000000000,'Mythic Family','Mythic Badge','Mythic Universe'),
  (50,54,50000000000,'God Family','God Badge','God Heaven'),
  (55,59,100000000000,'Titan Family','Titan Badge','Titan World'),
  (60,64,200000000000,'Conqueror Family','Conqueror Badge','Conqueror War'),
  (65,69,300000000000,'Celestial Family','Celestial Badge','Celestial Cloud'),
  (70,74,500000000000,'Divine Family','Divine Badge','Divine Light'),
  (75,79,1000000000000,'Immortal Family','Immortal Badge','Immortal Shadow'),
  (80,84,2000000000000,'Eternal Family','Eternal Badge','Eternal Flame'),
  (85,89,5000000000000,'Supreme Family','Supreme Badge','Supreme Ocean'),
  (90,94,10000000000000,'GOD Family','GOD Badge','GOD Realm'),
  (95,100,50000000000000,'GOD MYTHIC Family','GOD MYTHIC Badge','GOD MYTHIC Cover')
  ON CONFLICT (tierStart) DO NOTHING;

-- DAILY TARGET SYSTEM (Agency + DB) -----------------------------------------
CREATE TABLE IF NOT EXISTS AgencyTargetTiers (
  hostCountTier INTEGER PRIMARY KEY, -- 10, 20, 30 ...
  giftTarget BIGINT NOT NULL,
  reward INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS DbTargetTiers (
  agencyCountTier INTEGER PRIMARY KEY, -- 10, 20, 30 ...
  giftTarget BIGINT NOT NULL,
  reward INTEGER NOT NULL
);
-- Pattern from the spec: target = tier * 100,000, reward = tier * 10,000 (agency);
-- target = tier * 1,000,000, reward = tier * 50,000 (DB). Generated to tier 100.
INSERT INTO AgencyTargetTiers (hostCountTier, giftTarget, reward)
  SELECT n, n::bigint * 100000, n * 10000 FROM generate_series(10, 100, 10) AS n
  ON CONFLICT (hostCountTier) DO NOTHING;
INSERT INTO DbTargetTiers (agencyCountTier, giftTarget, reward)
  SELECT n, n::bigint * 1000000, n * 50000 FROM generate_series(10, 100, 10) AS n
  ON CONFLICT (agencyCountTier) DO NOTHING;

CREATE TABLE IF NOT EXISTS DailyTargetResults (
  id SERIAL PRIMARY KEY,
  resultDate DATE NOT NULL,
  entityType TEXT NOT NULL, -- agency | db | db_host
  entityId INTEGER NOT NULL, -- Agencies.id for 'agency'; Users.id for 'db'/'db_host'
  countValue INTEGER NOT NULL, -- host count or agency count used
  giftTotal BIGINT NOT NULL,
  tierReached INTEGER NOT NULL DEFAULT 0,
  reward INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending', -- pending | approved
  approvedAt TIMESTAMPTZ,
  UNIQUE (resultDate, entityType, entityId)
);

-- NEW USER 7-DAY TASK SYSTEM (replaces the old simple UserTask ladder) -----
CREATE TABLE IF NOT EXISTS TaskDefinitions (
  id SERIAL PRIMARY KEY,
  day INTEGER NOT NULL,
  orderInDay INTEGER NOT NULL,
  trackingKey TEXT NOT NULL UNIQUE, -- identifies the server-side progress check
  title TEXT NOT NULL,
  targetValue INTEGER NOT NULL DEFAULT 1,
  rewardCoins INTEGER NOT NULL DEFAULT 0,
  rewardItemCategory TEXT, -- frame | ride | roomcover | NULL
  rewardItemName TEXT,
  rewardItemDays INTEGER,
  manual BOOLEAN NOT NULL DEFAULT FALSE, -- true = no real tracking yet, user taps GO to self-report done
  active BOOLEAN NOT NULL DEFAULT TRUE
);
INSERT INTO TaskDefinitions (day, orderInDay, trackingKey, title, targetValue, rewardCoins, rewardItemCategory, rewardItemName, rewardItemDays, manual) VALUES
  (1,1,'bind_phone','Bind Phone Number',1,1000,NULL,NULL,NULL,FALSE),
  (1,2,'complete_profile','Complete Your Profile',1,0,'frame','Bronze Frame',3,FALSE),
  (1,3,'create_room','Create Your Room',1,0,'roomcover','Starter Room Cover',3,FALSE),
  (2,1,'enter_room','Enter Any Room',1,500,NULL,NULL,NULL,TRUE),
  (2,2,'receive_gift','Receive Any Gift from Someone',1,500,NULL,NULL,NULL,FALSE),
  (2,3,'chat_3_people','Chat with 3 People Total',3,500,NULL,NULL,NULL,FALSE),
  (3,1,'post_3_moments','Post 3 Posts on Moment',3,0,'frame','Pink Frame',3,FALSE),
  (3,2,'like_3_moments','Like 3 Posts on Moment',3,200,NULL,NULL,NULL,FALSE),
  (3,3,'comment_3_moments','Comment 3 Posts on Moment',3,500,NULL,NULL,NULL,FALSE),
  (4,1,'become_verified_or_family_supervised','Become Host or Agency or Join DB',1,500,NULL,NULL,NULL,FALSE),
  (4,2,'join_family','Join Any Family',1,500,NULL,NULL,NULL,FALSE),
  (5,1,'send_gift_1','Send Gift to 1 Person, Any Amount',1,500,NULL,NULL,NULL,FALSE),
  (5,2,'follow_5','Follow 5 Users Total',5,500,NULL,NULL,NULL,FALSE),
  (6,1,'invite_mic_3','Invite 3 People on Mic',3,1000,NULL,NULL,NULL,TRUE),
  (6,2,'stay_mic_10min','Stay on Mic for 10 Minutes Total',10,500,NULL,NULL,NULL,TRUE),
  (6,3,'gift_self_1000','Gift Yourself 1000 Coins',1000,500,NULL,NULL,NULL,FALSE),
  (7,1,'recharge_50000','Recharge 50,000 Coins',50000,10000,NULL,NULL,NULL,FALSE),
  (7,2,'send_level_2','Reach Send Level 2',2,2000,NULL,NULL,NULL,FALSE),
  (7,3,'receive_from_3_diff','Receive Gift from 3 Different People',3,2000,NULL,NULL,NULL,FALSE),
  (7,4,'send_to_3_diff','Send Gift to 3 Different People',3,2000,NULL,NULL,NULL,FALSE)
  ON CONFLICT (trackingKey) DO NOTHING;

ALTER TABLE Users ADD COLUMN IF NOT EXISTS taskStartAt TIMESTAMPTZ; -- set at phone verification
CREATE TABLE IF NOT EXISTS UserTaskProgress (
  userId INTEGER NOT NULL REFERENCES Users(id),
  taskDefId INTEGER NOT NULL REFERENCES TaskDefinitions(id),
  manualDone BOOLEAN NOT NULL DEFAULT FALSE, -- for manual/GO tasks
  claimed BOOLEAN NOT NULL DEFAULT FALSE,
  claimedAt TIMESTAMPTZ,
  PRIMARY KEY (userId, taskDefId)
);
CREATE TABLE IF NOT EXISTS UserGiftVouchers (
  userId INTEGER NOT NULL REFERENCES Users(id),
  giftName TEXT NOT NULL,
  quantity INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (userId, giftName)
);
INSERT INTO AppSettings (key, value) VALUES ('newuser_task_enabled', 'true') ON CONFLICT (key) DO NOTHING;
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
ALTER TABLE Gifts ADD COLUMN IF NOT EXISTS category TEXT DEFAULT 'OTHERS';
ALTER TABLE Gifts ADD COLUMN IF NOT EXISTS receiverSplitPct INTEGER NOT NULL DEFAULT 60;
ALTER TABLE Gifts ADD COLUMN IF NOT EXISTS isCustom BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE Gifts ADD COLUMN IF NOT EXISTS requestedByUserId INTEGER REFERENCES Users(id);
ALTER TABLE Gifts ADD COLUMN IF NOT EXISTS customStatus TEXT; -- pending | approved | rejected (custom gifts only)
ALTER TABLE Gifts ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT TRUE;

-- Animation tier is derived from price at read-time (see server.js), not stored.
-- NORMAL GIFTS catalog - fixed 60% receiver / 40% admin split, no odds/RTP.
INSERT INTO Gifts (name, icon, coinCost, category) VALUES
  ('Country Flag','🚩',20000,'FLAGS'),
  ('Suya Platter','🍢',500,'FOOD'), ('Shawarma','🌯',800,'FOOD'), ('Naman Rago','🍖',1000,'FOOD'),
  ('Rago Gaba','🐐',2000,'FOOD'), ('Seafood','🦐',3000,'FOOD'), ('Banquet','🍽️',5000,'FOOD'),
  ('Wedding Cake','🎂',8000,'FOOD'), ('BBQ Grill','🔥',10000,'FOOD'), ('Buffet VIP','🍱',15000,'FOOD'),
  ('Chef Table','👨‍🍳',20000,'FOOD'), ('Feast na Sarakuna','🥘',30000,'FOOD'), ('Abinci na Millionaire','🥂',40000,'FOOD'),
  ('Jollof Rice','🍛',600,'FOOD'), ('Pounded Yam','🍲',1200,'FOOD'), ('Eba','🥣',400,'FOOD'),
  ('Amala','🍜',700,'FOOD'), ('Tuwo Shinkafa','🍚',900,'FOOD'),
  ('Bread','🍞',100,'FOOD'), ('Egg','🥚',150,'FOOD'), ('Water','💧',100,'FOOD'), ('Akara','🧆',200,'FOOD'),
  ('Moi Moi','🫘',250,'FOOD'), ('Yam','🍠',300,'FOOD'), ('Plantain','🍌',350,'FOOD'), ('Beans','🫘',400,'FOOD'),
  ('Rice','🍚',450,'FOOD'), ('Noodles','🍜',500,'FOOD'), ('Soup','🥣',550,'FOOD'), ('Soda','🥤',200,'FOOD'),
  ('Fura','🥛',300,'FOOD'), ('Kunu','🥤',250,'FOOD'), ('Zobo','🧃',200,'FOOD'), ('Snack','🍪',100,'FOOD'),
  ('Chips','🍟',150,'FOOD'), ('Cake Slice','🍰',400,'FOOD'), ('Meat Pie','🥧',300,'FOOD'), ('Biscuit','🍪',100,'FOOD'),
  ('Flat','🏢',50000,'HOUSES'), ('Bungalow','🏘️',80000,'HOUSES'), ('Duplex','🏠',100000,'HOUSES'),
  ('Mansion','🏡',200000,'HOUSES'), ('Villa','🏰',300000,'HOUSES'), ('Estate','🏞️',400000,'HOUSES'),
  ('Penthouse','🏙️',600000,'HOUSES'), ('Palace','🏯',500000,'HOUSES'), ('Castle','🏰',2000000,'HOUSES'),
  ('Toyota Corolla','🚗',300000,'TRAVEL'), ('Honda Civic','🚗',400000,'TRAVEL'), ('Mercedes Benz','🚗',800000,'TRAVEL'),
  ('Range Rover','🚙',1200000,'TRAVEL'), ('Lamborghini','🏎️',5000000,'TRAVEL'), ('Ferrari','🏎️',6000000,'TRAVEL'),
  ('Honda Bike','🏍️',80000,'TRAVEL'), ('Yamaha','🏍️',150000,'TRAVEL'), ('Ducati','🏍️',500000,'TRAVEL'),
  ('Harley Davidson','🏍️',700000,'TRAVEL'), ('First Class Ticket','🎫',250000,'TRAVEL'),
  ('Helicopter','🚁',10000000,'TRAVEL'), ('Private Jet','✈️',50000000,'TRAVEL'),
  ('King Crown','🤴',1000000,'KINGDOM'), ('Queen Crown','👸',1000000,'KINGDOM'),
  ('iPhone SE','📱',70000,'IPHONE'), ('iPhone 11','📱',120000,'IPHONE'), ('iPhone 12','📱',180000,'IPHONE'),
  ('iPhone 13','📱',250000,'IPHONE'), ('iPhone 14','📱',350000,'IPHONE'), ('iPhone 15','📱',450000,'IPHONE'),
  ('iPhone 15 Pro','📱',600000,'IPHONE'), ('iPhone 15 Pro Max','📱',750000,'IPHONE'),
  ('Galaxy A14','📲',50000,'SAMSUNG'), ('Galaxy A54','📲',90000,'SAMSUNG'), ('Galaxy S21','📲',150000,'SAMSUNG'),
  ('Galaxy S22','📲',220000,'SAMSUNG'), ('Galaxy S23','📲',300000,'SAMSUNG'), ('Galaxy S23 Ultra','📲',400000,'SAMSUNG'),
  ('Galaxy Z Flip5','📲',550000,'SAMSUNG'), ('Galaxy Z Fold5','📲',700000,'SAMSUNG'),
  ('LG TV 32inch','📺',80000,'OTHERS'), ('Samsung TV 43inch','📺',120000,'OTHERS'), ('Sony TV 55inch','📺',200000,'OTHERS'),
  ('OLED TV 65inch','📺',350000,'OTHERS'), ('Smart TV 75inch','📺',500000,'OTHERS'),
  ('Laptop Macbook','💻',400000,'OTHERS'), ('Laptop HP','💻',250000,'OTHERS'), ('Laptop Dell','💻',200000,'OTHERS'),
  ('Fridge','🧊',150000,'OTHERS'), ('AC','❄️',180000,'OTHERS'), ('Generator 5KVA','⚡',300000,'OTHERS'),
  ('Diamond Ring','💍',1000000,'OTHERS'), ('Watch Rolex','⌚',500000,'OTHERS'), ('Bag Gucci','👜',80000,'OTHERS'),
  ('Shoes Nike','👟',15000,'OTHERS'), ('Perfume Chanel','🧴',25000,'OTHERS'),
  ('Animal Friend','🐾',300,'LUCKY WHEEL'), ('Animal Pal','🦊',1500,'LUCKY WHEEL'), ('Animal Guardian','🦁',8000,'LUCKY WHEEL'),
  ('Animal Legend','🐉',35000,'LUCKY WHEEL')
  ON CONFLICT DO NOTHING;

-- Migration: rename any already-seeded rows from the old 'ANIMALS' category
-- (safe to run every start - a no-op once the rename has happened).
UPDATE Gifts SET category = 'LUCKY WHEEL' WHERE category = 'ANIMALS';

-- LUCKY WHEEL (RTP mini-game) -------------------------------------------------
-- Sender's stake (the gift's coinCost) is wagered on a weighted-random
-- multiplier; the receiver gets multiplier x stake x receiverSplitPct as
-- diamonds. reservePool tracks admin's running balance for this feature -
-- it moves by (stake - payout) every spin, same as the RTP simulator used
-- to design this.
CREATE TABLE IF NOT EXISTS LuckyWheelSettings (
  id INTEGER PRIMARY KEY DEFAULT 1,
  targetRtp NUMERIC NOT NULL DEFAULT 94,
  receiverSplitPct INTEGER NOT NULL DEFAULT 45,
  maxLossStreak INTEGER NOT NULL DEFAULT 15,
  reservePool BIGINT NOT NULL DEFAULT 5000000,
  riskThresholdPct NUMERIC NOT NULL DEFAULT 8,
  updatedAt TIMESTAMPTZ DEFAULT now(),
  CONSTRAINT lucky_wheel_settings_single_row CHECK (id = 1)
);
INSERT INTO LuckyWheelSettings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS LuckyWheelOutcomes (
  id SERIAL PRIMARY KEY,
  multiplier NUMERIC NOT NULL,
  weightPct NUMERIC NOT NULL,
  sortOrder INTEGER NOT NULL DEFAULT 0
);
INSERT INTO LuckyWheelOutcomes (multiplier, weightPct, sortOrder)
SELECT * FROM (VALUES
  (0, 32.75, 1), (0.5, 12.16, 2), (1, 35, 3), (2, 20, 4),
  (99, 0.08, 5), (200, 0.015, 6), (500, 0.003, 7), (1000, 0.0005, 8)
) AS seed(multiplier, weightPct, sortOrder)
WHERE NOT EXISTS (SELECT 1 FROM LuckyWheelOutcomes);

-- Per-user pity counter: consecutive spins with multiplier < 1. When it
-- hits maxLossStreak, the next spin is drawn only from outcomes >= 1x.
ALTER TABLE Wallets ADD COLUMN IF NOT EXISTS luckyLossStreak INTEGER NOT NULL DEFAULT 0;

-- TRANSACTIONS (every coin movement) ----------------------------------------
CREATE TABLE IF NOT EXISTS Transactions (
  id SERIAL PRIMARY KEY,
  userId INTEGER NOT NULL REFERENCES Users(id),
  type TEXT NOT NULL,                    -- purchase | gift_sent | gift_received | task_reward | referral_bonus | withdrawal
  amount INTEGER NOT NULL,
  meta JSONB,
  createdAt TIMESTAMPTZ DEFAULT now()
);
ALTER TABLE Transactions ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'completed'; -- completed | pending

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
CREATE TABLE IF NOT EXISTS RoomSeats (
  streamId INTEGER NOT NULL REFERENCES LiveStreams(id),
  seatNumber INTEGER NOT NULL, -- 1-8
  userId INTEGER REFERENCES Users(id),
  occupiedAt TIMESTAMPTZ,
  PRIMARY KEY (streamId, seatNumber)
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
