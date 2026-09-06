// server.js
// Everything backend lives in this ONE file, on purpose:
//   - Express setup + static frontend serving
//   - Auth (register, login, phone OTP) + JWT middleware
//   - Wallet, Gifts, Referral, Tasks, Streams, Follow, Leaderboard routes
//   - Socket.io real-time layer (WebRTC signaling, chat, gifts)
// db.js stays separate (just the Postgres connection pool).

import path from "path";
import { fileURLToPath } from "url";
import express from "express";
import http from "http";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { customAlphabet } from "nanoid";
import { Server } from "socket.io";
import { query, initDb } from "./db.js";
import pool from "./db.js";

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, "public");
const JWT_SECRET = process.env.JWT_SECRET || "amana_live_super_secret_change_me";
const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:5173";

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: CLIENT_URL, methods: ["GET", "POST"] } });

app.use(cors({ origin: CLIENT_URL }));
app.use(express.json());

// =================================================================
// AUTH MIDDLEWARE - verifies "Authorization: Bearer <token>"
// =================================================================
function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "No auth token provided" });
  try {
    req.user = jwt.verify(token, JWT_SECRET); // { id, amanaId, username }
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// =================================================================
// HEALTH CHECK
// =================================================================
app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok", db: "connected" });
  } catch (err) {
    res.status(500).json({ status: "error", db: "disconnected", error: err.message });
  }
});

// =================================================================
// AUTH: register, login, phone OTP, /me
// =================================================================
const idGen = customAlphabet("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", 6);
function generateAmanaId() {
  return `AMN-${idGen()}`;
}
function signToken(user) {
  return jwt.sign({ id: user.id, amanaId: user.amanaid, username: user.username }, JWT_SECRET, { expiresIn: "7d" });
}
function publicUser(row) {
  return {
    id: row.id,
    amanaId: row.amanaid,
    username: row.username,
    email: row.email,
    phone: row.phone,
    phoneVerified: row.phoneverified,
    avatar: row.avatar,
    bio: row.bio,
    referredBy: row.referredby,
    createdAt: row.createdat,
    lastLoginAt: row.lastloginat,
    gender: row.gender,
    country: row.country,
    countryChangesUsed: row.countrychangesused,
    agencyId: row.agencyid,
    agencyApplicationStatus: row.agencyapplicationstatus,
    isHostBadge: row.ishostbadge,
    isDbBadge: row.isdbbadge,
    backgroundPics: row.backgroundpics || [],
    prettyId: row.prettyid,
    prettyIdExpiresAt: row.prettyidexpiresat,
  };
}

// The fixed 7-day task ladder (also used by /api/tasks below)
const DAY_TASKS = [
  { day: 1, title: "Complete your profile", rewardCoins: 20 },
  { day: 2, title: "Watch a live stream for 5 minutes", rewardCoins: 30 },
  { day: 3, title: "Send your first gift", rewardCoins: 40 },
  { day: 4, title: "Invite a friend using your AmanaID", rewardCoins: 50 },
  { day: 5, title: "Go live for the first time", rewardCoins: 60 },
  { day: 6, title: "Chat in 3 different live streams", rewardCoins: 70 },
  { day: 7, title: "Log in 7 days in a row - claim your bonus!", rewardCoins: 150 },
];
async function seedTasksForUser(userId) {
  for (const t of DAY_TASKS) {
    await query(
      `INSERT INTO UserTask (userId, day, title, rewardCoins, completed)
       VALUES ($1, $2, $3, $4, FALSE) ON CONFLICT (userId, day) DO NOTHING`,
      [userId, t.day, t.title, t.rewardCoins]
    );
  }
}

// NOTE: registration UI is intentionally not in the frontend yet (deferred
// until the rest of the app is finished) - but the endpoint itself works,
// so the first account(s) can be created with curl/Postman:
//   POST /api/auth/register  { "username", "email", "password" }
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, email, password, referralCode } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: "username, email and password are required" });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }
    const existing = await query("SELECT id FROM Users WHERE email = $1 OR username = $2", [email, username]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: "Email or username already in use" });
    }

    let referrer = null;
    if (referralCode) {
      const referrerResult = await query("SELECT * FROM Users WHERE amanaId = $1", [referralCode.trim()]);
      if (referrerResult.rows.length === 0) {
        return res.status(400).json({ error: "Invalid referral (AmanaID) code" });
      }
      referrer = referrerResult.rows[0];
    }

    const passwordHash = bcrypt.hashSync(password, 10);
    let amanaId = generateAmanaId();
    while (true) {
      const clash = await query("SELECT id FROM Users WHERE amanaId = $1", [amanaId]);
      if (clash.rows.length === 0) break;
      amanaId = generateAmanaId();
    }

    const insertResult = await query(
      `INSERT INTO Users (amanaId, username, email, passwordHash, referredBy)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [amanaId, username, email, passwordHash, referrer ? referrer.amanaid : null]
    );
    const user = insertResult.rows[0];

    await query("INSERT INTO Wallets (userId, coinBalance, diamondBalance) VALUES ($1, 0, 0)", [user.id]);
    await seedTasksForUser(user.id);

    if (referrer) {
      const bonus = 100;
      await query("INSERT INTO Referrals (referrerId, referredId, bonusCoins) VALUES ($1, $2, $3)", [
        referrer.id,
        user.id,
        bonus,
      ]);
      await query("UPDATE Wallets SET coinBalance = coinBalance + $1, updatedAt = now() WHERE userId = $2", [
        bonus,
        referrer.id,
      ]);
      await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1, 'referral_bonus', $2, $3)", [
        referrer.id,
        bonus,
        JSON.stringify({ referredUserId: user.id }),
      ]);
    }

    const token = signToken(user);
    res.status(201).json({ token, user: publicUser(user) });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "email and password are required" });
    const result = await query("SELECT * FROM Users WHERE email = $1", [email]);
    const user = result.rows[0];
    if (!user || !bcrypt.compareSync(password, user.passwordhash)) {
      return res.status(401).json({ error: "Invalid email or password" });
    }
    await query("UPDATE Users SET lastLoginAt = now() WHERE id = $1", [user.id]);
    const token = signToken(user);
    res.json({ token, user: publicUser(user) });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

// Phone OTP - no SMS provider configured, so the code is returned directly
// in the response for testing (see the frontend's OTP screen note).
app.post("/api/auth/otp/request", async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: "phone is required" });
    const code = String(Math.floor(100000 + Math.random() * 900000));
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
    await query("INSERT INTO PhoneOtps (phone, code, expiresAt) VALUES ($1, $2, $3)", [phone, code, expiresAt]);
    console.log(`[Amana Live] OTP for ${phone}: ${code} (no SMS provider configured)`);
    res.json({ message: "OTP generated - no SMS provider configured yet, code returned below.", devCode: code });
  } catch (err) {
    console.error("OTP request error:", err);
    res.status(500).json({ error: "Failed to generate OTP" });
  }
});

app.post("/api/auth/otp/verify", async (req, res) => {
  try {
    const { phone, code, userId } = req.body;
    if (!phone || !code) return res.status(400).json({ error: "phone and code are required" });
    const otpResult = await query(
      `SELECT * FROM PhoneOtps WHERE phone = $1 AND code = $2 AND consumed = FALSE ORDER BY id DESC LIMIT 1`,
      [phone, code]
    );
    const otp = otpResult.rows[0];
    if (!otp) return res.status(400).json({ error: "Invalid code" });
    if (new Date(otp.expiresat) < new Date()) {
      return res.status(400).json({ error: "Code expired, please request a new one" });
    }
    await query("UPDATE PhoneOtps SET consumed = TRUE WHERE id = $1", [otp.id]);
    if (userId) {
      const clash = await query("SELECT id FROM Users WHERE phone = $1 AND id != $2", [phone, userId]);
      if (clash.rows.length > 0) return res.status(409).json({ error: "Phone number already linked to another account" });
      await query("UPDATE Users SET phone = $1, phoneVerified = TRUE WHERE id = $2", [phone, userId]);
    }
    res.json({ verified: true });
  } catch (err) {
    console.error("OTP verify error:", err);
    res.status(500).json({ error: "Failed to verify OTP" });
  }
});

app.get("/api/auth/me", requireAuth, async (req, res) => {
  const result = await query("SELECT * FROM Users WHERE id = $1", [req.user.id]);
  if (result.rows.length === 0) return res.status(404).json({ error: "User not found" });
  res.json({ user: publicUser(result.rows[0]) });
});

// =================================================================
// WALLET
// =================================================================
app.get("/api/wallet", requireAuth, async (req, res) => {
  const result = await query("SELECT * FROM Wallets WHERE userId = $1", [req.user.id]);
  if (result.rows.length === 0) return res.status(404).json({ error: "Wallet not found" });
  const w = result.rows[0];
  res.json({ coinBalance: w.coinbalance, diamondBalance: w.diamondbalance, updatedAt: w.updatedat });
});

app.get("/api/wallet/transactions", requireAuth, async (req, res) => {
  const result = await query("SELECT * FROM Transactions WHERE userId = $1 ORDER BY id DESC LIMIT 50", [req.user.id]);
  res.json({
    transactions: result.rows.map((t) => ({ id: t.id, type: t.type, amount: t.amount, meta: t.meta, createdAt: t.createdat })),
  });
});

app.post("/api/wallet/purchase", requireAuth, async (req, res) => {
  const { coins } = req.body;
  if (!Number.isInteger(coins) || coins <= 0) return res.status(400).json({ error: "coins must be a positive integer" });
  await query("UPDATE Wallets SET coinBalance = coinBalance + $1, updatedAt = now() WHERE userId = $2", [coins, req.user.id]);
  await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1, 'purchase', $2, $3)", [
    req.user.id,
    coins,
    JSON.stringify({ note: "Simulated purchase - no payment gateway configured" }),
  ]);
  res.json({ message: `Purchased ${coins} coins (simulated)` });
});

app.post("/api/wallet/withdraw", requireAuth, async (req, res) => {
  const { diamonds } = req.body;
  if (!Number.isInteger(diamonds) || diamonds <= 0) return res.status(400).json({ error: "diamonds must be a positive integer" });
  const result = await query("SELECT diamondBalance FROM Wallets WHERE userId = $1", [req.user.id]);
  const wallet = result.rows[0];
  if (!wallet || wallet.diamondbalance < diamonds) return res.status(400).json({ error: "Insufficient diamond balance" });
  await query("UPDATE Wallets SET diamondBalance = diamondBalance - $1, updatedAt = now() WHERE userId = $2", [diamonds, req.user.id]);
  await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1, 'withdrawal', $2, $3)", [
    req.user.id,
    -diamonds,
    JSON.stringify({ note: "Simulated withdrawal - no payout gateway configured" }),
  ]);
  res.json({ message: `Withdrawal of ${diamonds} diamonds requested (simulated)` });
});

// =================================================================
// GIFTS - catalog + core send logic (reused by the socket handler below)
// =================================================================
app.get("/api/gifts", async (req, res) => {
  const result = await query("SELECT * FROM Gifts ORDER BY coinCost ASC");
  res.json({ gifts: result.rows.map((g) => ({ id: g.id, name: g.name, icon: g.icon, coinCost: g.coincost })) });
});

async function sendGift({ senderId, streamId, giftId }) {
  const giftResult = await query("SELECT * FROM Gifts WHERE id = $1", [giftId]);
  if (giftResult.rows.length === 0) throw new Error("Gift not found");
  const gift = giftResult.rows[0];

  const streamResult = await query("SELECT * FROM LiveStreams WHERE id = $1", [streamId]);
  if (streamResult.rows.length === 0) throw new Error("Stream not found");
  const stream = streamResult.rows[0];

  const walletResult = await query("SELECT * FROM Wallets WHERE userId = $1", [senderId]);
  const senderWallet = walletResult.rows[0];
  if (!senderWallet || senderWallet.coinbalance < gift.coincost) throw new Error("Insufficient coin balance");

  // 50/50 split: half to the host as diamonds, the other half is platform commission
  const hostShare = Math.floor(gift.coincost / 2);

  await query("UPDATE Wallets SET coinBalance = coinBalance - $1, updatedAt = now() WHERE userId = $2", [gift.coincost, senderId]);
  await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1, 'gift_sent', $2, $3)", [
    senderId,
    -gift.coincost,
    JSON.stringify({ streamId, giftId, giftName: gift.name }),
  ]);

  await query("UPDATE Wallets SET diamondBalance = diamondBalance + $1, updatedAt = now() WHERE userId = $2", [hostShare, stream.hostid]);
  await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1, 'gift_received', $2, $3)", [
    stream.hostid,
    hostShare,
    JSON.stringify({ streamId, giftId, giftName: gift.name, fromUserId: senderId }),
  ]);

  await query("UPDATE LiveStreams SET totalCoinsEarned = totalCoinsEarned + $1 WHERE id = $2", [gift.coincost, streamId]);

  return { hostId: stream.hostid, giftName: gift.name, icon: gift.icon, coinCost: gift.coincost, hostShare };
}

app.post("/api/gifts/send", requireAuth, async (req, res) => {
  try {
    const { streamId, giftId } = req.body;
    if (!streamId || !giftId) return res.status(400).json({ error: "streamId and giftId are required" });
    const result = await sendGift({ senderId: req.user.id, streamId, giftId });
    res.json({ message: "Gift sent", ...result });
  } catch (err) {
    res.status(400).json({ error: err.message || "Failed to send gift" });
  }
});

// =================================================================
// PROFILE - stats row, send/receive level, gift hall, live record,
// gender/country, pretty ID, agency apply/join, settings
// =================================================================

// Level formula: cumulative coins needed to REACH level L (L starting at 1)
// Send:    (L-1) * 100,000
// Receive: (L-1) * 50,000
// e.g. Level 2 Send = 100,000 coins, Level 2 Receive = 50,000 coins (matches spec).
const SEND_STEP = 100000;
const RECEIVE_STEP = 50000;
const MAX_LEVEL = 1000;
function levelFromTotal(total, step) {
  const level = Math.min(MAX_LEVEL, Math.floor(total / step) + 1);
  const intoLevel = total % step;
  const neededForNext = level >= MAX_LEVEL ? 0 : step - intoLevel;
  return { level, progressCoins: intoLevel, coinsToNextLevel: neededForNext, stepSize: step };
}

app.get("/api/profile/stats", requireAuth, async (req, res) => {
  const uid = req.user.id;
  const [following, fans, friends, sentSum, receivedSum] = await Promise.all([
    query("SELECT COUNT(*) FROM Follows WHERE followerId = $1", [uid]),
    query("SELECT COUNT(*) FROM Follows WHERE followedId = $1", [uid]),
    query(
      `SELECT COUNT(*) FROM Follows f1
       WHERE f1.followerId = $1
       AND EXISTS (SELECT 1 FROM Follows f2 WHERE f2.followerId = f1.followedId AND f2.followedId = $1)`,
      [uid]
    ),
    query("SELECT COALESCE(SUM(-amount),0) AS total FROM Transactions WHERE userId = $1 AND type = 'gift_sent'", [uid]),
    query("SELECT COALESCE(SUM(amount),0) AS total FROM Transactions WHERE userId = $1 AND type = 'gift_received'", [uid]),
  ]);
  const coinsSent = Number(sentSum.rows[0].total);
  const coinsReceived = Number(receivedSum.rows[0].total);
  res.json({
    following: Number(following.rows[0].count),
    fans: Number(fans.rows[0].count),
    friends: Number(friends.rows[0].count),
    coinsSent,
    coinsReceived,
    sendLevel: levelFromTotal(coinsSent, SEND_STEP),
    receiveLevel: levelFromTotal(coinsReceived, RECEIVE_STEP),
  });
});

app.post("/api/profile/gender", requireAuth, async (req, res) => {
  const { gender } = req.body;
  if (!["male", "female"].includes(gender)) return res.status(400).json({ error: "gender must be 'male' or 'female'" });
  const existing = await query("SELECT gender FROM Users WHERE id = $1", [req.user.id]);
  if (existing.rows[0].gender) return res.status(400).json({ error: "Gender can only be set once and cannot be changed" });
  await query("UPDATE Users SET gender = $1 WHERE id = $2", [gender, req.user.id]);
  res.json({ message: "Gender updated", gender });
});

app.post("/api/profile/country", requireAuth, async (req, res) => {
  const { country } = req.body;
  if (!country) return res.status(400).json({ error: "country is required" });
  const result = await query("SELECT countryChangesUsed FROM Users WHERE id = $1", [req.user.id]);
  const used = result.rows[0].countrychangesused || 0;
  if (used >= 2) return res.status(400).json({ error: "Country can only be changed 2 times. Limit reached." });
  await query("UPDATE Users SET country = $1, countryChangesUsed = countryChangesUsed + 1 WHERE id = $2", [country, req.user.id]);
  res.json({ message: "Country updated", country, changesRemaining: 1 - used });
});

app.get("/api/profile/gifts", requireAuth, async (req, res) => {
  const uid = req.user.id;
  const [sent, received] = await Promise.all([
    query(
      `SELECT meta->>'giftName' AS name, COUNT(*) AS count FROM Transactions
       WHERE userId = $1 AND type = 'gift_sent' GROUP BY meta->>'giftName' ORDER BY count DESC`,
      [uid]
    ),
    query(
      `SELECT meta->>'giftName' AS name, COUNT(*) AS count FROM Transactions
       WHERE userId = $1 AND type = 'gift_received' GROUP BY meta->>'giftName' ORDER BY count DESC`,
      [uid]
    ),
  ]);
  res.json({
    sent: sent.rows.map((r) => ({ name: r.name || "Gift", count: Number(r.count) })),
    received: received.rows.map((r) => ({ name: r.name || "Gift", count: Number(r.count) })),
  });
});

app.get("/api/profile/live-record", requireAuth, async (req, res) => {
  const userResult = await query("SELECT clearedLiveRecordAt FROM Users WHERE id = $1", [req.user.id]);
  const since = userResult.rows[0].clearedliverecordat || "1970-01-01";
  const result = await query(
    `SELECT
       to_char(startedAt, 'YYYY-MM-DD') AS day,
       COUNT(*) AS rooms,
       COALESCE(SUM(EXTRACT(EPOCH FROM (COALESCE(endedAt, now()) - startedAt)) / 60), 0) AS minutes,
       COALESCE(SUM(totalCoinsEarned), 0) AS giftsReceived
     FROM LiveStreams
     WHERE hostId = $1 AND startedAt > $2
     GROUP BY day ORDER BY day DESC LIMIT 30`,
    [req.user.id, since]
  );
  res.json({
    days: result.rows.map((r) => ({
      day: r.day,
      minutes: Math.round(Number(r.minutes)),
      hours: Math.round((Number(r.minutes) / 60) * 10) / 10,
      giftsReceived: Number(r.giftsreceived),
      rooms: Number(r.rooms),
    })),
  });
});

app.get("/api/profile/pretty-id/check", async (req, res) => {
  const value = (req.query.value || "").trim();
  if (!value) return res.status(400).json({ error: "value is required" });
  const clash = await query("SELECT id FROM Users WHERE LOWER(prettyId) = LOWER($1) OR LOWER(amanaId) = LOWER($1)", [value]);
  res.json({ available: clash.rows.length === 0 });
});

app.post("/api/profile/pretty-id/purchase", requireAuth, async (req, res) => {
  const { value } = req.body;
  if (!value || value.trim().length < 3) return res.status(400).json({ error: "Pretty ID must be at least 3 characters" });
  const clash = await query("SELECT id FROM Users WHERE (LOWER(prettyId) = LOWER($1) OR LOWER(amanaId) = LOWER($1)) AND id != $2", [
    value,
    req.user.id,
  ]);
  if (clash.rows.length > 0) return res.status(409).json({ error: "This Pretty ID is not available" });
  const walletResult = await query("SELECT coinBalance FROM Wallets WHERE userId = $1", [req.user.id]);
  const PRICE = 1000000;
  if (!walletResult.rows[0] || walletResult.rows[0].coinbalance < PRICE) return res.status(400).json({ error: "Insufficient coin balance (needs 1,000,000 coins)" });
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
  await query("UPDATE Wallets SET coinBalance = coinBalance - $1, updatedAt = now() WHERE userId = $2", [PRICE, req.user.id]);
  await query("UPDATE Users SET prettyId = $1, prettyIdExpiresAt = $2 WHERE id = $3", [value, expiresAt, req.user.id]);
  await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1, 'purchase', $2, $3)", [
    req.user.id,
    -PRICE,
    JSON.stringify({ note: "Pretty ID purchase", value }),
  ]);
  res.json({ message: "Pretty ID purchased", prettyId: value, expiresAt });
});

app.post("/api/profile/agency/apply", requireAuth, async (req, res) => {
  const { dbId } = req.body;
  if (!dbId) return res.status(400).json({ error: "dbId is required" });
  const userResult = await query("SELECT phoneVerified FROM Users WHERE id = $1", [req.user.id]);
  if (!userResult.rows[0].phoneverified) return res.status(400).json({ error: "You must bind your phone number before applying" });
  await query("UPDATE Users SET agencyApplicationStatus = 'pending', agencyApplicationDbId = $1 WHERE id = $2", [dbId, req.user.id]);
  res.json({ message: "Application submitted. An admin will review it." });
});

app.post("/api/profile/agency/join", requireAuth, async (req, res) => {
  const { agencyId } = req.body;
  if (!agencyId) return res.status(400).json({ error: "agencyId is required" });
  const userResult = await query("SELECT phoneVerified FROM Users WHERE id = $1", [req.user.id]);
  if (!userResult.rows[0].phoneverified) return res.status(400).json({ error: "You must bind your phone number before joining an agency" });
  const agencyResult = await query("SELECT id, name FROM Agencies WHERE id = $1", [agencyId]);
  if (agencyResult.rows.length === 0) return res.status(404).json({ error: "Agency not found - check the Agency ID" });
  await query("UPDATE Users SET agencyId = $1, agencyApplicationStatus = 'none' WHERE id = $2", [agencyId, req.user.id]);
  res.json({ message: `Joined agency: ${agencyResult.rows[0].name}` });
});

app.post("/api/profile/security/pin", requireAuth, async (req, res) => {
  const { pin } = req.body;
  if (!/^\d{6}$/.test(pin || "")) return res.status(400).json({ error: "PIN must be exactly 6 digits" });
  const pinHash = await bcrypt.hash(pin, 10);
  await query("UPDATE Users SET loginPinHash = $1 WHERE id = $2", [pinHash, req.user.id]);
  res.json({ message: "6-digit login PIN saved" });
});

app.post("/api/profile/settings/clear-storage", requireAuth, async (req, res) => {
  await query("UPDATE Users SET clearedMessagesAt = now(), clearedLiveRecordAt = now() WHERE id = $1", [req.user.id]);
  res.json({ message: "Messages and Live Record cleared. Level and items were kept." });
});

// =================================================================
// REFERRAL
// =================================================================
app.get("/api/referral", requireAuth, async (req, res) => {
  const userResult = await query("SELECT amanaId FROM Users WHERE id = $1", [req.user.id]);
  if (userResult.rows.length === 0) return res.status(404).json({ error: "User not found" });

  const referralsResult = await query(
    `SELECT r.id, r.bonusCoins, r.createdAt, u.username, u.amanaId
     FROM Referrals r JOIN Users u ON u.id = r.referredId
     WHERE r.referrerId = $1 ORDER BY r.id DESC`,
    [req.user.id]
  );
  const totalBonus = referralsResult.rows.reduce((sum, r) => sum + r.bonuscoins, 0);

  res.json({
    amanaId: userResult.rows[0].amanaid,
    referralLink: `https://amana.live/register?ref=${userResult.rows[0].amanaid}`,
    totalReferred: referralsResult.rows.length,
    totalBonusCoinsEarned: totalBonus,
    referrals: referralsResult.rows.map((r) => ({
      username: r.username,
      amanaId: r.amanaid,
      bonusCoins: r.bonuscoins,
      createdAt: r.createdat,
    })),
  });
});

// =================================================================
// TASKS (7-Day onboarding ladder)
// =================================================================
app.get("/api/tasks", requireAuth, async (req, res) => {
  const userId = req.user.id;
  const userResult = await query("SELECT createdAt FROM Users WHERE id = $1", [userId]);
  if (userResult.rows.length === 0) return res.status(404).json({ error: "User not found" });

  const createdAt = new Date(userResult.rows[0].createdat);
  const daysSinceSignup = Math.floor((Date.now() - createdAt.getTime()) / (1000 * 60 * 60 * 24)) + 1;

  const tasksResult = await query("SELECT * FROM UserTask WHERE userId = $1 ORDER BY day ASC", [userId]);
  const tasks = tasksResult.rows.map((t) => ({
    day: t.day,
    title: t.title,
    rewardCoins: t.rewardcoins,
    completed: t.completed,
    completedAt: t.completedat,
    unlocked: t.day <= Math.min(daysSinceSignup, 7),
  }));

  res.json({ tasks, daysSinceSignup: Math.min(daysSinceSignup, 7) });
});

app.post("/api/tasks/:day/complete", requireAuth, async (req, res) => {
  const userId = req.user.id;
  const day = Number(req.params.day);
  if (!Number.isInteger(day) || day < 1 || day > 7) return res.status(400).json({ error: "day must be between 1 and 7" });

  const userResult = await query("SELECT createdAt FROM Users WHERE id = $1", [userId]);
  const createdAt = new Date(userResult.rows[0].createdat);
  const daysSinceSignup = Math.floor((Date.now() - createdAt.getTime()) / (1000 * 60 * 60 * 24)) + 1;
  if (day > daysSinceSignup) return res.status(400).json({ error: "This task is not unlocked yet" });

  const taskResult = await query("SELECT * FROM UserTask WHERE userId = $1 AND day = $2", [userId, day]);
  if (taskResult.rows.length === 0) return res.status(404).json({ error: "Task not found" });
  const task = taskResult.rows[0];
  if (task.completed) return res.status(400).json({ error: "Task already completed" });

  await query("UPDATE UserTask SET completed = TRUE, completedAt = now() WHERE userId = $1 AND day = $2", [userId, day]);
  await query("UPDATE Wallets SET coinBalance = coinBalance + $1, updatedAt = now() WHERE userId = $2", [task.rewardcoins, userId]);
  await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1, 'task_reward', $2, $3)", [
    userId,
    task.rewardcoins,
    JSON.stringify({ day }),
  ]);

  res.json({ message: "Task completed", rewardCoins: task.rewardcoins });
});

// =================================================================
// STREAMS (Home v3 Live tab, Go Live, Follow tab's "Rooms You Manage")
// =================================================================
const streamKeyGen = customAlphabet("abcdefghijklmnopqrstuvwxyz0123456789", 10);

const STREAM_SELECT = `
  SELECT s.*, u.username AS hostUsername, u.avatar AS hostAvatar, u.createdAt AS hostCreatedAt,
         a.name AS agencyName,
         (SELECT COUNT(*)::int FROM RoomAdmins ra WHERE ra.streamId = s.id) + 1 AS hostCount,
         (SELECT completed FROM UserTask t WHERE t.userId = s.hostId AND t.day = 1) AS day1Completed
  FROM LiveStreams s
  JOIN Users u ON u.id = s.hostId
  LEFT JOIN Agencies a ON a.id = u.agencyId
`;

function computeCategory(row) {
  if (row.roomtype === "video") return "Video";
  if (row.roomtype === "pk") return "PK";
  if (row.hostcount > 2) return "Party";
  const hostAgeDays = (Date.now() - new Date(row.hostcreatedat).getTime()) / (1000 * 60 * 60 * 24);
  if (hostAgeDays < 7 && row.day1completed === false) return "New";
  return "Stage";
}
function serializeStream(row) {
  return {
    id: row.id,
    streamKey: row.streamkey,
    title: row.title,
    hostId: row.hostid,
    hostUsername: row.hostusername,
    hostAvatar: row.hostavatar,
    agencyName: row.agencyname,
    viewerCount: row.viewercount,
    hostCount: row.hostcount,
    roomType: row.roomtype,
    category: computeCategory(row),
    totalCoinsEarned: row.totalcoinsearned,
    startedAt: row.startedat,
  };
}

app.get("/api/streams/live", async (req, res) => {
  const result = await query(`${STREAM_SELECT} WHERE s.status = 'live' ORDER BY s.viewerCount DESC, s.startedAt DESC`);
  res.json({ streams: result.rows.map(serializeStream) });
});

app.post("/api/streams/start", requireAuth, async (req, res) => {
  const { title, roomType } = req.body;
  const streamKey = streamKeyGen();
  const safeRoomType = ["stage", "pk"].includes(roomType) ? roomType : "stage";
  const result = await query(
    `INSERT INTO LiveStreams (streamKey, hostId, title, status, roomType) VALUES ($1, $2, $3, 'live', $4) RETURNING *`,
    [streamKey, req.user.id, title || `${req.user.username}'s Live`, safeRoomType]
  );
  const stream = result.rows[0];
  res.status(201).json({
    id: stream.id,
    streamKey: stream.streamkey,
    title: stream.title,
    status: stream.status,
    roomType: stream.roomtype,
    startedAt: stream.startedat,
  });
});

app.post("/api/streams/:id/end", requireAuth, async (req, res) => {
  const { id } = req.params;
  const streamResult = await query("SELECT * FROM LiveStreams WHERE id = $1", [id]);
  const stream = streamResult.rows[0];
  if (!stream) return res.status(404).json({ error: "Stream not found" });
  if (stream.hostid !== req.user.id) return res.status(403).json({ error: "Only the host can end this stream" });
  await query("UPDATE LiveStreams SET status = 'ended', endedAt = now() WHERE id = $1", [id]);
  res.json({ message: "Stream ended" });
});

app.get("/api/streams/mine/admin", requireAuth, async (req, res) => {
  const result = await query(
    `${STREAM_SELECT} WHERE s.status = 'live' AND (s.hostId = $1 OR s.id IN (SELECT streamId FROM RoomAdmins WHERE userId = $1)) ORDER BY s.startedAt DESC`,
    [req.user.id]
  );
  res.json({ streams: result.rows.map(serializeStream) });
});

app.get("/api/streams/:id", async (req, res) => {
  const { id } = req.params;
  const streamResult = await query(`${STREAM_SELECT} WHERE s.id = $1`, [id]);
  const stream = streamResult.rows[0];
  if (!stream) return res.status(404).json({ error: "Stream not found" });
  const chatResult = await query("SELECT * FROM ChatMessages WHERE streamId = $1 ORDER BY id DESC LIMIT 50", [id]);
  res.json({
    stream: serializeStream(stream),
    chatHistory: chatResult.rows.reverse().map((c) => ({ username: c.username, message: c.message, createdAt: c.createdat })),
  });
});

// =================================================================
// FOLLOW (Follow tab: top stories, followed rooms)
// =================================================================
app.post("/api/follow/:userId", requireAuth, async (req, res) => {
  const followedId = Number(req.params.userId);
  if (followedId === req.user.id) return res.status(400).json({ error: "You can't follow yourself" });
  const target = await query("SELECT id FROM Users WHERE id = $1", [followedId]);
  if (target.rows.length === 0) return res.status(404).json({ error: "User not found" });
  await query(`INSERT INTO Follows (followerId, followedId) VALUES ($1, $2) ON CONFLICT (followerId, followedId) DO NOTHING`, [
    req.user.id,
    followedId,
  ]);
  res.json({ message: "Followed" });
});

app.delete("/api/follow/:userId", requireAuth, async (req, res) => {
  await query("DELETE FROM Follows WHERE followerId = $1 AND followedId = $2", [req.user.id, Number(req.params.userId)]);
  res.json({ message: "Unfollowed" });
});

app.post("/api/follow/:userId/pin", requireAuth, async (req, res) => {
  const followedId = Number(req.params.userId);
  const result = await query(
    "UPDATE Follows SET pinned = NOT pinned WHERE followerId = $1 AND followedId = $2 RETURNING pinned",
    [req.user.id, followedId]
  );
  if (result.rows.length === 0) return res.status(404).json({ error: "You don't follow this user" });
  res.json({ pinned: result.rows[0].pinned });
});

// Public profile of ANY user (no email/phone - those stay private) -------
app.get("/api/users/:id/profile", requireAuth, async (req, res) => {
  const targetId = Number(req.params.id);
  const result = await query(
    "SELECT id, amanaId, username, bio, gender, country, createdAt, agencyId, isHostBadge, isDbBadge, prettyId FROM Users WHERE id = $1",
    [targetId]
  );
  if (result.rows.length === 0) return res.status(404).json({ error: "User not found" });
  const row = result.rows[0];
  const [following, fans, friends, sentSum, receivedSum, isFollowing] = await Promise.all([
    query("SELECT COUNT(*) FROM Follows WHERE followerId = $1", [targetId]),
    query("SELECT COUNT(*) FROM Follows WHERE followedId = $1", [targetId]),
    query(
      `SELECT COUNT(*) FROM Follows f1
       WHERE f1.followerId = $1
       AND EXISTS (SELECT 1 FROM Follows f2 WHERE f2.followerId = f1.followedId AND f2.followedId = $1)`,
      [targetId]
    ),
    query("SELECT COALESCE(SUM(-amount),0) AS total FROM Transactions WHERE userId = $1 AND type = 'gift_sent'", [targetId]),
    query("SELECT COALESCE(SUM(amount),0) AS total FROM Transactions WHERE userId = $1 AND type = 'gift_received'", [targetId]),
    query("SELECT 1 FROM Follows WHERE followerId = $1 AND followedId = $2", [req.user.id, targetId]),
  ]);
  res.json({
    id: row.id,
    amanaId: row.amanaid,
    username: row.username,
    bio: row.bio,
    gender: row.gender,
    country: row.country,
    createdAt: row.createdat,
    agencyId: row.agencyid,
    isHostBadge: row.ishostbadge,
    isDbBadge: row.isdbbadge,
    prettyId: row.prettyid,
    isSelf: targetId === req.user.id,
    isFollowing: isFollowing.rows.length > 0,
    stats: {
      following: Number(following.rows[0].count),
      fans: Number(fans.rows[0].count),
      friends: Number(friends.rows[0].count),
      coinsSent: Number(sentSum.rows[0].total),
      coinsReceived: Number(receivedSum.rows[0].total),
    },
  });
});

// Search for people by username or AmanaID/Pretty ID ----------------------
app.get("/api/users/search", requireAuth, async (req, res) => {
  const q = (req.query.q || "").trim();
  if (!q) return res.json({ users: [] });
  const result = await query(
    `SELECT id, amanaId, username, prettyId FROM Users
     WHERE username ILIKE $1 OR amanaId ILIKE $1 OR prettyId ILIKE $1
     LIMIT 20`,
    [`%${q}%`]
  );
  res.json({
    users: result.rows.map((r) => ({ id: r.id, amanaId: r.amanaid, username: r.username, prettyId: r.prettyid })),
  });
});

app.get("/api/follow/stories", requireAuth, async (req, res) => {
  const result = await query(
    `SELECT u.id, u.username, u.avatar, f.pinned,
            EXISTS(SELECT 1 FROM LiveStreams s WHERE s.hostId = u.id AND s.status = 'live') AS isLive
     FROM Follows f JOIN Users u ON u.id = f.followedId
     WHERE f.followerId = $1 ORDER BY f.pinned DESC, isLive DESC, u.username ASC`,
    [req.user.id]
  );
  res.json({
    stories: result.rows.map((r) => ({ userId: r.id, username: r.username, avatar: r.avatar, pinned: r.pinned, isLive: r.islive })),
  });
});

app.get("/api/follow/rooms", requireAuth, async (req, res) => {
  const result = await query(
    `SELECT s.id, s.streamKey, s.title, s.viewerCount, u.username AS hostUsername, u.avatar AS hostAvatar
     FROM LiveStreams s JOIN Users u ON u.id = s.hostId
     WHERE s.status = 'live' AND s.hostId IN (SELECT followedId FROM Follows WHERE followerId = $1)
     ORDER BY s.viewerCount DESC`,
    [req.user.id]
  );
  res.json({
    rooms: result.rows.map((r) => ({
      id: r.id,
      streamKey: r.streamkey,
      title: r.title,
      viewerCount: r.viewercount,
      hostUsername: r.hostusername,
      hostAvatar: r.hostavatar,
    })),
  });
});

// =================================================================
// LEADERBOARD (agency / giftwall / roomwall / host - Daily/Weekly/Monthly)
// =================================================================
const GMT1_OFFSET_MS = 60 * 60 * 1000;
function periodStart(period) {
  const nowGmt1 = new Date(Date.now() + GMT1_OFFSET_MS);
  let startGmt1;
  if (period === "weekly") {
    const day = nowGmt1.getUTCDay();
    startGmt1 = new Date(nowGmt1);
    startGmt1.setUTCDate(nowGmt1.getUTCDate() - day);
    startGmt1.setUTCHours(0, 0, 0, 0);
  } else if (period === "monthly") {
    startGmt1 = new Date(Date.UTC(nowGmt1.getUTCFullYear(), nowGmt1.getUTCMonth(), 1, 0, 0, 0));
  } else {
    startGmt1 = new Date(Date.UTC(nowGmt1.getUTCFullYear(), nowGmt1.getUTCMonth(), nowGmt1.getUTCDate(), 0, 0, 0));
  }
  return new Date(startGmt1.getTime() - GMT1_OFFSET_MS);
}
const RESET_NOTE = {
  daily: "Resets: Daily at 23:59 (GMT+1)",
  weekly: "Resets: Weekly on Sunday 23:59 (GMT+1)",
  monthly: "Resets: Monthly, on the last day (GMT+1)",
};
const PRIZES = {
  agency: "#1 Agency gets the Home Banner for 1 week",
  giftwall: "Top 3 get a special profile frame",
  roomwall: "#1 Room gets featured on the Home Banner",
  host: "Top Host gets a verified badge",
};

app.get("/api/leaderboard/:type", async (req, res) => {
  const { type } = req.params;
  const period = ["daily", "weekly", "monthly"].includes(req.query.period) ? req.query.period : "daily";
  const since = periodStart(period);

  let rows;
  if (type === "agency") {
    const result = await query(
      `SELECT a.id, a.name, COALESCE(SUM(t.amount), 0)::int AS value
       FROM Agencies a JOIN Users u ON u.agencyId = a.id
       LEFT JOIN Transactions t ON t.userId = u.id AND t.type = 'gift_received' AND t.createdAt >= $1
       GROUP BY a.id, a.name ORDER BY value DESC LIMIT 10`,
      [since]
    );
    rows = result.rows;
  } else if (type === "giftwall") {
    const result = await query(
      `SELECT u.id, u.username AS name, COALESCE(SUM(ABS(t.amount)), 0)::int AS value
       FROM Transactions t JOIN Users u ON u.id = t.userId
       WHERE t.type = 'gift_sent' AND t.createdAt >= $1
       GROUP BY u.id, u.username ORDER BY value DESC LIMIT 10`,
      [since]
    );
    rows = result.rows;
  } else if (type === "roomwall") {
    const result = await query(
      `SELECT s.id, s.title AS name, COALESCE(SUM(ABS(t.amount)), 0)::int AS value
       FROM Transactions t JOIN LiveStreams s ON s.id = (t.meta->>'streamId')::int
       WHERE t.type = 'gift_sent' AND t.createdAt >= $1
       GROUP BY s.id, s.title ORDER BY value DESC LIMIT 10`,
      [since]
    );
    rows = result.rows;
  } else if (type === "host") {
    const result = await query(
      `SELECT u.id, u.username AS name, COALESCE(SUM(t.amount), 0)::int AS value
       FROM Transactions t JOIN Users u ON u.id = t.userId
       WHERE t.type = 'gift_received' AND t.createdAt >= $1
       GROUP BY u.id, u.username ORDER BY value DESC LIMIT 10`,
      [since]
    );
    rows = result.rows;
  } else {
    return res.status(400).json({ error: "Unknown leaderboard type. Use agency, giftwall, roomwall, or host." });
  }

  res.json({
    type,
    period,
    resetNote: RESET_NOTE[period],
    prize: PRIZES[type],
    ranking: rows.map((r, i) => ({ rank: i + 1, id: r.id, name: r.name, value: r.value })),
  });
});

// =================================================================
// Fallback 404 for unknown API routes (must be BEFORE static/catch-all)
// =================================================================
app.use("/api", (req, res) => res.status(404).json({ error: "Not found" }));

// =================================================================
// STATIC FRONTEND (public/index.html - the whole app, one file)
// =================================================================
app.use(express.static(PUBLIC_DIR));
app.get("*", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "index.html"), (err) => {
    if (err) res.status(200).send("Amana Live API is running, but public/index.html was not found.");
  });
});

// =================================================================
// SOCKET.IO - WebRTC signaling, chat, gifts, viewer counts
// =================================================================
const roomViewers = new Map(); // streamKey -> Set of socket ids

function getSocketUser(socket) {
  const token = socket.handshake.auth?.token;
  if (!token) return null;
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

async function leaveRoom(socket, streamKey) {
  socket.leave(streamKey);
  const set = roomViewers.get(streamKey);
  if (set) {
    set.delete(socket.id);
    const count = set.size;
    io.to(streamKey).emit("viewer-count", { count });
    io.to(streamKey).emit("peer-left", { socketId: socket.id });
    try {
      await query("UPDATE LiveStreams SET viewerCount = $1 WHERE streamKey = $2", [count, streamKey]);
    } catch (err) {
      console.error("Failed to persist viewer count on leave:", err);
    }
    if (count === 0) roomViewers.delete(streamKey);
  }
}

io.on("connection", (socket) => {
  const user = getSocketUser(socket); // null for anonymous viewers
  socket.data.user = user;

  socket.on("join-room", async ({ streamKey }) => {
    socket.join(streamKey);
    socket.data.streamKey = streamKey;
    if (!roomViewers.has(streamKey)) roomViewers.set(streamKey, new Set());
    roomViewers.get(streamKey).add(socket.id);
    const count = roomViewers.get(streamKey).size;

    await query(`UPDATE LiveStreams SET viewerCount = $1, peakViewers = GREATEST(peakViewers, $1) WHERE streamKey = $2`, [
      count,
      streamKey,
    ]);
    io.to(streamKey).emit("viewer-count", { count });
    socket.to(streamKey).emit("peer-joined", { socketId: socket.id, username: user?.username || "Guest" });
  });

  socket.on("leave-room", ({ streamKey }) => leaveRoom(socket, streamKey));
  socket.on("disconnect", () => {
    if (socket.data.streamKey) leaveRoom(socket, socket.data.streamKey);
  });

  // WebRTC signaling (mesh: host <-> each viewer is its own PeerConnection)
  socket.on("webrtc-offer", ({ to, offer }) => io.to(to).emit("webrtc-offer", { from: socket.id, offer }));
  socket.on("webrtc-answer", ({ to, answer }) => io.to(to).emit("webrtc-answer", { from: socket.id, answer }));
  socket.on("webrtc-ice-candidate", ({ to, candidate }) => io.to(to).emit("webrtc-ice-candidate", { from: socket.id, candidate }));

  // Chat
  socket.on("chat-message", async ({ streamId, streamKey, message }) => {
    if (!message || !message.trim()) return;
    const username = user?.username || "Guest";
    if (streamId) {
      await query("INSERT INTO ChatMessages (streamId, userId, username, message) VALUES ($1, $2, $3, $4)", [
        streamId,
        user?.id || null,
        username,
        message.slice(0, 500),
      ]);
    }
    io.to(streamKey).emit("chat-message", { username, message: message.slice(0, 500), createdAt: new Date().toISOString() });
  });

  // Gifts sent live during a stream
  socket.on("send-gift", async ({ streamId, streamKey, giftId }) => {
    if (!user) return socket.emit("gift-error", { error: "You must be logged in to send gifts" });
    try {
      const result = await sendGift({ senderId: user.id, streamId, giftId });
      io.to(streamKey).emit("gift-received", {
        fromUsername: user.username,
        giftName: result.giftName,
        icon: result.icon,
        coinCost: result.coinCost,
      });
    } catch (err) {
      socket.emit("gift-error", { error: err.message || "Failed to send gift" });
    }
  });
});

// =================================================================
// START - schema/seed data are ensured automatically before the server
// starts accepting requests, no separate "npm run db:init" step needed.
// =================================================================
const PORT = process.env.PORT || 5000;

initDb()
  .then(() => {
    server.listen(PORT, () => {
      console.log(`✅ Amana Live running on http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error("❌ Failed to initialize the database:", err);
    process.exit(1);
  });
