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
  const vip = await getVipInfo(req.user.id);
  const levels = vip.vipLevel ? await getVipLevels() : [];
  const discountPct = vip.vipLevel ? levels.find((l) => l.level === vip.vipLevel)?.purchaseDiscountPct || 0 : 0;
  const bonusCoins = Math.round(coins * (discountPct / 100));
  const totalCoins = coins + bonusCoins;
  await query("UPDATE Wallets SET coinBalance = coinBalance + $1, updatedAt = now() WHERE userId = $2", [totalCoins, req.user.id]);
  await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1, 'purchase', $2, $3)", [
    req.user.id,
    totalCoins,
    JSON.stringify({ note: "Simulated purchase - no payment gateway configured", basePurchase: coins, vipBonus: bonusCoins }),
  ]);
  await query("INSERT INTO SystemMessages (userId, type, content) VALUES ($1, 'recharge', $2)", [
    req.user.id,
    bonusCoins > 0 ? `You recharged ${coins} coins (+${bonusCoins} VIP bonus).` : `You recharged ${coins} coins successfully.`,
  ]);
  res.json({ message: `Purchased ${totalCoins} coins${bonusCoins ? ` (includes ${bonusCoins} VIP bonus)` : ""} (simulated)` });
});

app.post("/api/wallet/withdraw", requireAuth, async (req, res) => {
  const { diamonds } = req.body;
  if (!Number.isInteger(diamonds) || diamonds <= 0) return res.status(400).json({ error: "diamonds must be a positive integer" });
  const result = await query("SELECT diamondBalance FROM Wallets WHERE userId = $1", [req.user.id]);
  const wallet = result.rows[0];
  if (!wallet || wallet.diamondbalance < diamonds) return res.status(400).json({ error: "Insufficient diamond balance" });
  await query("UPDATE Wallets SET diamondBalance = diamondBalance - $1, updatedAt = now() WHERE userId = $2", [diamonds, req.user.id]);
  const vip = await getVipInfo(req.user.id);
  const levels = vip.vipLevel ? await getVipLevels() : [];
  const userPct = vip.vipLevel ? levels.find((l) => l.level === vip.vipLevel)?.exchangeUserPct || 70 : 70;
  const usdValue = ((diamonds / 100000) * userPct) / 100;
  await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1, 'withdrawal', $2, $3)", [
    req.user.id,
    -diamonds,
    JSON.stringify({ note: "Simulated withdrawal - no payout gateway configured", exchangeUserPct: userPct, usdValue }),
  ]);
  await query("INSERT INTO SystemMessages (userId, type, content) VALUES ($1, 'withdraw', $2)", [
    req.user.id,
    `Your withdrawal request for ${diamonds} diamonds (≈$${usdValue.toFixed(2)} at ${userPct}% VIP rate) was submitted.`,
  ]);
  res.json({ message: `Withdrawal of ${diamonds} diamonds (≈$${usdValue.toFixed(2)}) requested (simulated)` });
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

  // Snapshot totals before the gift so we can tell if this gift crosses a
  // Room / Send / Receive level boundary (levels never reset, cosmetics only).
  const [roomBefore, senderBefore, receiverBefore] = await Promise.all([
    getRoomCoinsTotal(stream.hostid),
    getSendReceiveTotals(senderId),
    getSendReceiveTotals(stream.hostid),
  ]);

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

  // Fire level-up notifications (no-op unless a bracket/level was actually crossed).
  await Promise.all([
    notifyIfLeveledUp(stream.hostid, "Room", "RoomLevelTiers", roomBefore, roomBefore + gift.coincost, "task"),
    notifyIfLeveledUp(senderId, "Send Level", "SendLevelTiers", senderBefore.sent, senderBefore.sent + gift.coincost, "task"),
    notifyIfLeveledUp(stream.hostid, "Receive Level", "ReceiveLevelTiers", receiverBefore.received, receiverBefore.received + hostShare, "task"),
  ]);

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
  const vip = await getVipInfo(uid);
  const [sendTiers, receiveTiers] = await Promise.all([getTiers("SendLevelTiers"), getTiers("ReceiveLevelTiers")]);
  res.json({
    following: Number(following.rows[0].count),
    fans: Number(fans.rows[0].count),
    friends: Number(friends.rows[0].count),
    coinsSent,
    coinsReceived,
    sendLevel: computeLevelStatus(coinsSent, sendTiers),
    receiveLevel: computeLevelStatus(coinsReceived, receiveTiers),
    vipLevel: vip.vipLevel,
    vipTitle: vip.vipTitle,
    vipBadgeColor: vip.vipBadgeColor,
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
  await query("INSERT INTO SystemMessages (userId, type, content) VALUES ($1, 'task', $2)", [
    userId,
    `Day ${day} task complete! You earned ${task.rewardcoins} coins.`,
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
  if (targetId !== req.user.id) {
    await query("INSERT INTO ProfileViews (viewerId, viewedId) VALUES ($1, $2)", [req.user.id, targetId]);
  }
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
  const vip = await getVipInfo(targetId);
  const [sendTiers2, receiveTiers2] = await Promise.all([getTiers("SendLevelTiers"), getTiers("ReceiveLevelTiers")]);
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
    vipLevel: vip.vipLevel,
    vipTitle: vip.vipTitle,
    vipBadgeColor: vip.vipBadgeColor,
    isSelf: targetId === req.user.id,
    isFollowing: isFollowing.rows.length > 0,
    stats: {
      following: Number(following.rows[0].count),
      fans: Number(fans.rows[0].count),
      friends: Number(friends.rows[0].count),
      coinsSent: Number(sentSum.rows[0].total),
      coinsReceived: Number(receivedSum.rows[0].total),
      sendLevel: computeLevelStatus(Number(sentSum.rows[0].total), sendTiers2).level,
      receiveLevel: computeLevelStatus(Number(receivedSum.rows[0].total), receiveTiers2).level,
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

// =================================================================
// MESSAGE - Hello/Official/System tabs, Visit Notice, Square, Friends
// =================================================================
const HELLO_FREE_LIMIT = 3;
async function areFriends(idA, idB) {
  const r = await query(
    `SELECT 1 FROM Follows a WHERE a.followerId=$1 AND a.followedId=$2
     AND EXISTS (SELECT 1 FROM Follows b WHERE b.followerId=$2 AND b.followedId=$1)`,
    [idA, idB]
  );
  return r.rows.length > 0;
}

app.get("/api/messages/conversations", requireAuth, async (req, res) => {
  const type = req.query.type === "friends" ? "friends" : "hello";
  const me = req.user.id;
  const result = await query(
    `SELECT DISTINCT ON (other) other, u.username, u.prettyId, m.content AS lastContent, m.createdAt AS lastAt,
       (SELECT COUNT(*) FROM Messages WHERE senderId = other AND receiverId = $1 AND readAt IS NULL AND deletedForReceiver = FALSE) AS unread
     FROM (
       SELECT CASE WHEN senderId = $1 THEN receiverId ELSE senderId END AS other, content, createdAt
       FROM Messages WHERE (senderId = $1 OR receiverId = $1)
         AND NOT ((senderId = $1 AND deletedForSender) OR (receiverId = $1 AND deletedForReceiver))
       ORDER BY createdAt DESC
     ) m
     JOIN Users u ON u.id = m.other
     ORDER BY other, m.createdAt DESC`,
    [me]
  );
  const filtered = [];
  for (const row of result.rows) {
    const friend = await areFriends(me, row.other);
    if ((type === "friends") === friend) filtered.push(row);
  }
  res.json({
    conversations: filtered.map((r) => ({
      userId: r.other,
      username: r.username,
      prettyId: r.prettyid,
      lastMessage: r.lastcontent,
      lastAt: r.lastat,
      unread: Number(r.unread),
    })),
  });
});

app.get("/api/messages/thread/:userId", requireAuth, async (req, res) => {
  const otherId = Number(req.params.userId);
  const me = req.user.id;
  const result = await query(
    `SELECT m.*, g.name AS giftName FROM Messages m LEFT JOIN Gifts g ON g.id = m.giftId
     WHERE ((senderId = $1 AND receiverId = $2 AND deletedForSender = FALSE)
        OR (senderId = $2 AND receiverId = $1 AND deletedForReceiver = FALSE))
     ORDER BY createdAt ASC LIMIT 200`,
    [me, otherId]
  );
  await query("UPDATE Messages SET readAt = now() WHERE senderId = $1 AND receiverId = $2 AND readAt IS NULL", [otherId, me]);
  res.json({
    messages: result.rows.map((m) => ({
      id: m.id,
      senderId: m.senderid,
      receiverId: m.receiverid,
      content: m.content,
      giftName: m.giftname,
      createdAt: m.createdat,
    })),
  });
});

app.post("/api/messages/send", requireAuth, async (req, res) => {
  const { receiverId, content, giftId } = req.body;
  const me = req.user.id;
  if (!receiverId || (!content && !giftId)) return res.status(400).json({ error: "receiverId and content or giftId are required" });
  const friend = await areFriends(me, receiverId);
  if (!friend) {
    const sentCount = await query("SELECT COUNT(*) FROM Messages WHERE senderId = $1 AND receiverId = $2", [me, receiverId]);
    if (Number(sentCount.rows[0].count) >= HELLO_FREE_LIMIT) {
      return res.status(400).json({ error: `You've used your ${HELLO_FREE_LIMIT} free Hello Messages to this person. Become friends to keep chatting.` });
    }
  }
  if (giftId) {
    const walletResult = await query("SELECT coinBalance FROM Wallets WHERE userId = $1", [me]);
    const giftResult = await query("SELECT id, name, coinCost FROM Gifts WHERE id = $1", [giftId]);
    if (giftResult.rows.length === 0) return res.status(404).json({ error: "Gift not found" });
    const gift = giftResult.rows[0];
    if (!walletResult.rows[0] || walletResult.rows[0].coinbalance < gift.coincost) return res.status(400).json({ error: "Insufficient coins" });
    const [senderBefore, receiverBefore] = await Promise.all([getSendReceiveTotals(me), getSendReceiveTotals(receiverId)]);
    await query("UPDATE Wallets SET coinBalance = coinBalance - $1 WHERE userId = $2", [gift.coincost, me]);
    await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1,'gift_sent',$2,$3)", [
      me, -gift.coincost, JSON.stringify({ giftName: gift.name, via: "message" }),
    ]);
    await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1,'gift_received',$2,$3)", [
      receiverId, gift.coincost, JSON.stringify({ giftName: gift.name, via: "message" }),
    ]);
    await Promise.all([
      notifyIfLeveledUp(me, "Send Level", "SendLevelTiers", senderBefore.sent, senderBefore.sent + gift.coincost, "task"),
      notifyIfLeveledUp(receiverId, "Receive Level", "ReceiveLevelTiers", receiverBefore.received, receiverBefore.received + gift.coincost, "task"),
    ]);
  }
  const result = await query(
    "INSERT INTO Messages (senderId, receiverId, content, giftId) VALUES ($1,$2,$3,$4) RETURNING id, createdAt",
    [me, receiverId, content || null, giftId || null]
  );
  res.json({ message: "Sent", id: result.rows[0].id, createdAt: result.rows[0].createdat });
});

app.patch("/api/messages/thread/:userId/mark-unread", requireAuth, async (req, res) => {
  await query(
    `UPDATE Messages SET readAt = NULL WHERE id = (
       SELECT id FROM Messages WHERE senderId = $1 AND receiverId = $2 ORDER BY createdAt DESC LIMIT 1
     )`,
    [Number(req.params.userId), req.user.id]
  );
  res.json({ message: "Marked as unread" });
});

app.delete("/api/messages/thread/:userId", requireAuth, async (req, res) => {
  const otherId = Number(req.params.userId);
  const me = req.user.id;
  await query("UPDATE Messages SET deletedForSender = TRUE WHERE senderId = $1 AND receiverId = $2", [me, otherId]);
  await query("UPDATE Messages SET deletedForReceiver = TRUE WHERE senderId = $1 AND receiverId = $2", [otherId, me]);
  res.json({ message: "Conversation deleted" });
});

app.post("/api/messages/:id/report", requireAuth, async (req, res) => {
  const { reason } = req.body;
  await query("INSERT INTO MessageReports (messageId, reportedBy, reason) VALUES ($1,$2,$3)", [
    Number(req.params.id), req.user.id, reason || "Not specified",
  ]);
  res.json({ message: "Reported. Our team will review this." });
});

app.get("/api/messages/visits", requireAuth, async (req, res) => {
  const result = await query(
    `SELECT DISTINCT ON (viewerId) viewerId, u.username, u.prettyId, pv.createdAt
     FROM ProfileViews pv JOIN Users u ON u.id = pv.viewerId
     WHERE pv.viewedId = $1 ORDER BY viewerId, pv.createdAt DESC`,
    [req.user.id]
  );
  const rows = result.rows.sort((a, b) => new Date(b.createdat) - new Date(a.createdat));
  res.json({ visits: rows.map((r) => ({ userId: r.viewerid, username: r.username, prettyId: r.prettyid, viewedAt: r.createdat })) });
});

app.get("/api/messages/square", requireAuth, async (req, res) => {
  const userResult = await query("SELECT country FROM Users WHERE id = $1", [req.user.id]);
  const country = req.query.country || userResult.rows[0].country;
  if (!country) return res.json({ country: null, messages: [] });
  const result = await query(
    `SELECT sm.id, sm.content, sm.createdAt, u.username FROM SquareMessages sm
     JOIN Users u ON u.id = sm.userId WHERE sm.country = $1 ORDER BY sm.createdAt DESC LIMIT 100`,
    [country]
  );
  res.json({ country, messages: result.rows.reverse().map((r) => ({ id: r.id, username: r.username, content: r.content, createdAt: r.createdat })) });
});
app.post("/api/messages/square", requireAuth, async (req, res) => {
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: "content is required" });
  const userResult = await query("SELECT country FROM Users WHERE id = $1", [req.user.id]);
  const country = userResult.rows[0].country;
  if (!country) return res.status(400).json({ error: "Set your country in Edit Profile before posting to Square" });
  await query("INSERT INTO SquareMessages (userId, country, content) VALUES ($1,$2,$3)", [req.user.id, country, content]);
  res.json({ message: "Posted" });
});

app.get("/api/messages/official", requireAuth, async (req, res) => {
  const result = await query("SELECT id, title, content, createdAt FROM OfficialMessages ORDER BY createdAt DESC LIMIT 50");
  res.json({ messages: result.rows });
});

app.get("/api/messages/system", requireAuth, async (req, res) => {
  const result = await query("SELECT id, type, content, createdAt, readAt FROM SystemMessages WHERE userId = $1 ORDER BY createdAt DESC LIMIT 100", [
    req.user.id,
  ]);
  await query("UPDATE SystemMessages SET readAt = now() WHERE userId = $1 AND readAt IS NULL", [req.user.id]);
  res.json({ messages: result.rows });
});

// =================================================================
// LEVEL SYSTEM - Room / Send / Receive (cosmetics only, never resets)
// =================================================================
// Simple in-process cache so 1000 concurrent users don't re-hit the DB for
// tier tables on every gift/profile load. Cleared whenever an admin edits a
// tier (see the PATCH endpoints below).
const tierCache = {};
async function getTiers(table) {
  if (tierCache[table]) return tierCache[table];
  const result = await query(`SELECT * FROM ${table} ORDER BY tierStart ASC`);
  const tiers = result.rows.map((r) => ({
    tierStart: r.tierstart,
    tierEnd: r.tierend,
    threshold: Number(r.threshold),
    colorHex: r.colorhex,
    name: r.name,
    effect: r.effect,
  }));
  tierCache[table] = tiers;
  return tiers;
}
function invalidateTierCache(table) {
  delete tierCache[table];
}
// Interpolates a smooth per-level position (not just per-bracket) within
// whichever bracket the total currently falls into, e.g. "Lv.25: 300M/500M".
function computeLevelStatus(total, tiers) {
  let bracket = tiers[0];
  for (const t of tiers) if (total >= t.threshold) bracket = t;
  const bracketIndex = tiers.indexOf(bracket);
  const next = tiers[bracketIndex + 1];
  const levelsInBracket = bracket.tierEnd - bracket.tierStart + 1;
  const bracketRange = next ? next.threshold - bracket.threshold : 0;
  let level = bracket.tierStart;
  let progressPct = 100;
  let coinsToNextLevel = 0;
  if (next && bracketRange > 0) {
    const intoBracket = total - bracket.threshold;
    const levelOffset = Math.min(levelsInBracket - 1, Math.floor((intoBracket / bracketRange) * levelsInBracket));
    level = bracket.tierStart + levelOffset;
    const levelSpan = bracketRange / levelsInBracket;
    const levelStartCoins = bracket.threshold + levelOffset * levelSpan;
    progressPct = Math.min(100, Math.round(((total - levelStartCoins) / levelSpan) * 100));
    coinsToNextLevel = Math.max(0, Math.round(levelStartCoins + levelSpan - total));
  } else if (!next) {
    level = bracket.tierEnd;
  }
  return {
    level,
    total,
    tierName: bracket.name,
    colorHex: bracket.colorHex,
    effect: bracket.effect,
    progressPct,
    coinsToNextLevel,
    nextTierName: next ? next.name : null,
    nextTierAtLevel: next ? next.tierStart : null,
    unlockedTierStarts: tiers.filter((t) => t.threshold <= total).map((t) => t.tierStart),
  };
}
async function getRoomCoinsTotal(hostId) {
  const r = await query("SELECT COALESCE(SUM(totalCoinsEarned),0) AS total FROM LiveStreams WHERE hostId = $1", [hostId]);
  return Number(r.rows[0].total);
}
async function getSendReceiveTotals(userId) {
  const [sent, received] = await Promise.all([
    query("SELECT COALESCE(SUM(-amount),0) AS total FROM Transactions WHERE userId = $1 AND type = 'gift_sent'", [userId]),
    query("SELECT COALESCE(SUM(amount),0) AS total FROM Transactions WHERE userId = $1 AND type = 'gift_received'", [userId]),
  ]);
  return { sent: Number(sent.rows[0].total), received: Number(received.rows[0].total) };
}
// Called after a gift changes someone's totals; notifies only on an actual
// level-up (bracket or level boundary crossed), never on every gift.
async function notifyIfLeveledUp(userId, kind, table, beforeTotal, afterTotal, messageType) {
  const tiers = await getTiers(table);
  const before = computeLevelStatus(beforeTotal, tiers);
  const after = computeLevelStatus(afterTotal, tiers);
  if (after.level > before.level) {
    const unlockedNew = after.tierName !== before.tierName;
    const content = unlockedNew
      ? `Level up! ${kind} ${before.level} -> ${after.level}. ${after.tierName} unlocked!`
      : `Level up! ${kind} ${before.level} -> ${after.level}.`;
    await query("INSERT INTO SystemMessages (userId, type, content) VALUES ($1,$2,$3)", [userId, messageType, content]);
  }
}

app.get("/api/levels/room", requireAuth, async (req, res) => {
  const tiers = await getTiers("RoomLevelTiers");
  const total = await getRoomCoinsTotal(req.user.id);
  const status = computeLevelStatus(total, tiers);
  const userResult = await query("SELECT selectedRoomCoverTier FROM Users WHERE id = $1", [req.user.id]);
  res.json({ status, tiers, selectedCoverTier: userResult.rows[0].selectedroomcovertier });
});
app.post("/api/levels/room/select-cover", requireAuth, async (req, res) => {
  const { tierStart } = req.body;
  const total = await getRoomCoinsTotal(req.user.id);
  const tiers = await getTiers("RoomLevelTiers");
  const status = computeLevelStatus(total, tiers);
  if (!status.unlockedTierStarts.includes(tierStart)) return res.status(400).json({ error: "That Room Cover isn't unlocked yet" });
  await query("UPDATE Users SET selectedRoomCoverTier = $1 WHERE id = $2", [tierStart, req.user.id]);
  res.json({ message: "Room Cover updated" });
});
app.get("/api/levels/send", requireAuth, async (req, res) => {
  const tiers = await getTiers("SendLevelTiers");
  const { sent } = await getSendReceiveTotals(req.user.id);
  res.json({ status: computeLevelStatus(sent, tiers), tiers });
});
app.get("/api/levels/receive", requireAuth, async (req, res) => {
  const tiers = await getTiers("ReceiveLevelTiers");
  const { received } = await getSendReceiveTotals(req.user.id);
  res.json({ status: computeLevelStatus(received, tiers), tiers });
});
// Admin-style tier edits - no admin auth system exists yet (see VIP section
// note below); locking this down is a prerequisite before public launch.
app.patch("/api/levels/:kind/:tierStart", requireAuth, async (req, res) => {
  const tableMap = { room: "RoomLevelTiers", send: "SendLevelTiers", receive: "ReceiveLevelTiers" };
  const table = tableMap[req.params.kind];
  if (!table) return res.status(400).json({ error: "kind must be room, send, or receive" });
  const { threshold, name, colorHex, effect } = req.body;
  const fields = [];
  const params = [];
  let i = 1;
  if (threshold !== undefined) { fields.push(`threshold = $${i++}`); params.push(threshold); }
  if (name !== undefined) { fields.push(`name = $${i++}`); params.push(name); }
  if (colorHex !== undefined) { fields.push(`colorHex = $${i++}`); params.push(colorHex); }
  if (effect !== undefined && table === "RoomLevelTiers") { fields.push(`effect = $${i++}`); params.push(effect); }
  if (fields.length === 0) return res.status(400).json({ error: "Nothing to update" });
  params.push(Number(req.params.tierStart));
  await query(`UPDATE ${table} SET ${fields.join(", ")} WHERE tierStart = $${i}`, params);
  invalidateTierCache(table);
  res.json({ message: "Tier updated" });
});

// =================================================================
// VIP SYSTEM - levels, monthly spend, daily claim, priority sorting
// =================================================================
async function getVipLevels() {
  const result = await query("SELECT * FROM VipLevels ORDER BY level ASC");
  return result.rows.map((r) => ({
    level: r.level,
    title: r.title,
    spendRequired: Number(r.spendrequired),
    dailyClaimCoins: r.dailyclaimcoins,
    badgeColor: r.badgecolor,
    purchaseDiscountPct: r.purchasediscountpct,
    exchangeUserPct: r.exchangeuserpct,
  }));
}
async function getMonthlySpend(userId) {
  const result = await query(
    `SELECT COALESCE(SUM(-amount),0) AS total FROM Transactions
     WHERE userId = $1 AND amount < 0 AND type IN ('gift_sent','purchase')
     AND createdAt >= date_trunc('month', now())`,
    [userId]
  );
  return Number(result.rows[0].total);
}
function vipLevelForSpend(spend, levels) {
  let current = null;
  for (const lv of levels) if (spend >= lv.spendRequired) current = lv;
  return current; // null = no VIP level yet
}
// Reusable helper other sections (Moments, Profile, Leaderboard) can call.
async function getVipInfo(userId) {
  const levels = await getVipLevels();
  const spend = await getMonthlySpend(userId);
  const current = vipLevelForSpend(spend, levels);
  return { vipLevel: current ? current.level : 0, vipTitle: current ? current.title : null, vipBadgeColor: current ? current.badgeColor : null };
}

app.get("/api/vip/status", requireAuth, async (req, res) => {
  const levels = await getVipLevels();
  const spend = await getMonthlySpend(req.user.id);
  const current = vipLevelForSpend(spend, levels);
  const next = levels.find((lv) => lv.level === (current ? current.level + 1 : 1));
  const userResult = await query("SELECT vipLastClaimAt FROM Users WHERE id = $1", [req.user.id]);
  const lastClaim = userResult.rows[0].viplastclaimat;
  const msSinceClaim = lastClaim ? Date.now() - new Date(lastClaim).getTime() : Infinity;
  const cooldownMs = 24 * 60 * 60 * 1000;
  const canClaim = !!current && msSinceClaim >= cooldownMs;
  res.json({
    currentLevel: current ? current.level : 0,
    currentTitle: current ? current.title : "Not a VIP yet",
    badgeColor: current ? current.badgeColor : null,
    spentThisMonth: spend,
    nextLevel: next ? { level: next.level, title: next.title, spendRequired: next.spendRequired, coinsNeeded: Math.max(0, next.spendRequired - spend) } : null,
    progressPct: next ? Math.min(100, Math.round((spend / next.spendRequired) * 100)) : 100,
    dailyClaimCoins: current ? current.dailyClaimCoins : 0,
    canClaim,
    msUntilNextClaim: canClaim || !current ? 0 : Math.max(0, cooldownMs - msSinceClaim),
    purchaseDiscountPct: current ? current.purchaseDiscountPct : 0,
    exchangeUserPct: current ? current.exchangeUserPct : 70,
  });
});

app.post("/api/vip/claim", requireAuth, async (req, res) => {
  const levels = await getVipLevels();
  const spend = await getMonthlySpend(req.user.id);
  const current = vipLevelForSpend(spend, levels);
  if (!current) return res.status(400).json({ error: "You are not a VIP member yet" });
  const userResult = await query("SELECT vipLastClaimAt FROM Users WHERE id = $1", [req.user.id]);
  const lastClaim = userResult.rows[0].viplastclaimat;
  const msSinceClaim = lastClaim ? Date.now() - new Date(lastClaim).getTime() : Infinity;
  if (msSinceClaim < 24 * 60 * 60 * 1000) return res.status(400).json({ error: "You already claimed today. Come back after 24 hours." });
  await query("UPDATE Wallets SET coinBalance = coinBalance + $1, updatedAt = now() WHERE userId = $2", [current.dailyClaimCoins, req.user.id]);
  await query("UPDATE Users SET vipLastClaimAt = now() WHERE id = $1", [req.user.id]);
  await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1,'vip_daily_claim',$2,$3)", [
    req.user.id, current.dailyClaimCoins, JSON.stringify({ vipLevel: current.level }),
  ]);
  await query("INSERT INTO SystemMessages (userId, type, content) VALUES ($1,'recharge',$2)", [
    req.user.id, `VIP ${current.level} daily claim: +${current.dailyClaimCoins} coins.`,
  ]);
  res.json({ message: `Claimed ${current.dailyClaimCoins} coins`, coins: current.dailyClaimCoins });
});

app.get("/api/vip/levels", async (req, res) => {
  res.json({ levels: await getVipLevels() });
});

// Level-config update - no dedicated admin login exists yet in this build,
// so this is left callable but should be locked behind a real Admin role
// before this app goes live to the public.
app.patch("/api/vip/levels/:level", requireAuth, async (req, res) => {
  const { spendRequired, dailyClaimCoins } = req.body;
  const fields = [];
  const params = [];
  let i = 1;
  if (spendRequired !== undefined) { fields.push(`spendRequired = $${i++}`); params.push(spendRequired); }
  if (dailyClaimCoins !== undefined) { fields.push(`dailyClaimCoins = $${i++}`); params.push(dailyClaimCoins); }
  if (fields.length === 0) return res.status(400).json({ error: "Nothing to update" });
  params.push(Number(req.params.level));
  await query(`UPDATE VipLevels SET ${fields.join(", ")} WHERE level = $${i}`, params);
  res.json({ message: "VIP level updated" });
});

// =================================================================
// MOMENTS - Discovery/New/Follow feed, post cards, image viewer data
// =================================================================
async function fetchMomentUsername(text) {
  // Pulls @username tokens out of a caption so they can be tagged.
  const matches = text.match(/@([a-zA-Z0-9_]+)/g) || [];
  return [...new Set(matches.map((m) => m.slice(1)))];
}

app.post("/api/moments", requireAuth, async (req, res) => {
  const { text, images } = req.body;
  const imgArr = Array.isArray(images) ? images.slice(0, 9) : [];
  if (!text && imgArr.length === 0) return res.status(400).json({ error: "Add text or at least one image" });
  const result = await query("INSERT INTO Moments (userId, text, images) VALUES ($1,$2,$3) RETURNING id, createdAt", [
    req.user.id,
    text || null,
    JSON.stringify(imgArr),
  ]);
  const momentId = result.rows[0].id;
  const mentionedUsernames = await fetchMomentUsername(text || "");
  if (mentionedUsernames.length) {
    const tagged = await query("SELECT id FROM Users WHERE username = ANY($1)", [mentionedUsernames]);
    for (const row of tagged.rows) {
      await query("INSERT INTO MomentTags (momentId, userId) VALUES ($1,$2) ON CONFLICT DO NOTHING", [momentId, row.id]);
    }
  }
  res.json({ message: "Posted", id: momentId, createdAt: result.rows[0].createdat });
});

function momentCardRow(row, meId) {
  return {
    id: row.id,
    userId: row.userid,
    username: row.username,
    prettyId: row.prettyid,
    agencyId: row.agencyid,
    isHostBadge: row.ishostbadge,
    isDbBadge: row.isdbbadge,
    phoneVerified: row.phoneverified,
    vipLevel: row.viplevel || 0,
    vipBadgeColor: row.vipbadgecolor,
    // Simple activity-based "Social Level" S1-S10 (posts + engagement received)
    socialLevel: Math.min(10, Math.floor((Number(row.postcount) * 5 + Number(row.likesreceived) + Number(row.commentsreceived) * 2) / 50) + 1),
    text: row.text,
    images: row.images || [],
    createdAt: row.createdat,
    likeCount: Number(row.likecount),
    commentCount: Number(row.commentcount),
    isLiked: row.isliked,
    isSaved: row.issaved,
    isFollowing: row.isfollowing,
    isSelf: row.userid === meId,
  };
}

const MOMENT_SELECT = `
  SELECT m.*, u.username, u.prettyId, u.agencyId, u.isHostBadge, u.isDbBadge, u.phoneVerified,
    (SELECT COUNT(*) FROM Moments m2 WHERE m2.userId = m.userId) AS postCount,
    (SELECT COUNT(*) FROM MomentLikes ml2 JOIN Moments m3 ON m3.id = ml2.momentId WHERE m3.userId = m.userId) AS likesReceived,
    (SELECT COUNT(*) FROM MomentComments mc2 JOIN Moments m4 ON m4.id = mc2.momentId WHERE m4.userId = m.userId) AS commentsReceived,
    (SELECT COUNT(*) FROM MomentLikes WHERE momentId = m.id) AS likeCount,
    (SELECT COUNT(*) FROM MomentComments WHERE momentId = m.id) AS commentCount,
    EXISTS(SELECT 1 FROM MomentLikes WHERE momentId = m.id AND userId = $1) AS isLiked,
    EXISTS(SELECT 1 FROM MomentSaves WHERE momentId = m.id AND userId = $1) AS isSaved,
    EXISTS(SELECT 1 FROM Follows WHERE followerId = $1 AND followedId = m.userId) AS isFollowing,
    (SELECT MAX(vl.level) FROM VipLevels vl WHERE vl.spendRequired <= (
       SELECT COALESCE(SUM(-t.amount),0) FROM Transactions t WHERE t.userId = m.userId AND t.amount < 0
         AND t.type IN ('gift_sent','purchase') AND t.createdAt >= date_trunc('month', now())
     )) AS vipLevel,
    (SELECT vl2.badgeColor FROM VipLevels vl2 WHERE vl2.level = (SELECT MAX(vl3.level) FROM VipLevels vl3 WHERE vl3.spendRequired <= (
       SELECT COALESCE(SUM(-t2.amount),0) FROM Transactions t2 WHERE t2.userId = m.userId AND t2.amount < 0
         AND t2.type IN ('gift_sent','purchase') AND t2.createdAt >= date_trunc('month', now())
     ))) AS vipBadgeColor
  FROM Moments m JOIN Users u ON u.id = m.userId`;

app.get("/api/moments", requireAuth, async (req, res) => {
  const tab = req.query.tab === "follow" ? "follow" : req.query.tab === "new" ? "new" : "discovery";
  const page = Math.max(0, Number(req.query.page) || 0);
  const limit = 10;
  const offset = page * limit;
  let sql, params;
  if (tab === "follow") {
    sql = `${MOMENT_SELECT} WHERE m.userId IN (SELECT followedId FROM Follows WHERE followerId = $1) ORDER BY m.createdAt DESC LIMIT $2 OFFSET $3`;
    params = [req.user.id, limit, offset];
  } else if (tab === "new") {
    sql = `${MOMENT_SELECT} ORDER BY m.createdAt DESC LIMIT $2 OFFSET $3`;
    params = [req.user.id, limit, offset];
  } else {
    // Discovery: a simple recency+engagement recommendation, not a real ML ranking
    sql = `${MOMENT_SELECT} ORDER BY ((SELECT COUNT(*) FROM MomentLikes WHERE momentId = m.id) * 2 + (SELECT COUNT(*) FROM MomentComments WHERE momentId = m.id)) DESC, m.createdAt DESC LIMIT $2 OFFSET $3`;
    params = [req.user.id, limit, offset];
  }
  const result = await query(sql, params);
  res.json({ moments: result.rows.map((r) => momentCardRow(r, req.user.id)), hasMore: result.rows.length === limit });
});

app.get("/api/moments/:id", requireAuth, async (req, res) => {
  const result = await query(`${MOMENT_SELECT} WHERE m.id = $2`, [req.user.id, Number(req.params.id)]);
  if (result.rows.length === 0) return res.status(404).json({ error: "Moment not found" });
  res.json({ moment: momentCardRow(result.rows[0], req.user.id) });
});

app.delete("/api/moments/:id", requireAuth, async (req, res) => {
  const result = await query("DELETE FROM Moments WHERE id = $1 AND userId = $2 RETURNING id", [Number(req.params.id), req.user.id]);
  if (result.rows.length === 0) return res.status(404).json({ error: "Moment not found or not yours" });
  res.json({ message: "Deleted" });
});

app.post("/api/moments/:id/like", requireAuth, async (req, res) => {
  await query("INSERT INTO MomentLikes (momentId, userId) VALUES ($1,$2) ON CONFLICT DO NOTHING", [Number(req.params.id), req.user.id]);
  res.json({ message: "Liked" });
});
app.delete("/api/moments/:id/like", requireAuth, async (req, res) => {
  await query("DELETE FROM MomentLikes WHERE momentId = $1 AND userId = $2", [Number(req.params.id), req.user.id]);
  res.json({ message: "Unliked" });
});
app.post("/api/moments/:id/save", requireAuth, async (req, res) => {
  await query("INSERT INTO MomentSaves (momentId, userId) VALUES ($1,$2) ON CONFLICT DO NOTHING", [Number(req.params.id), req.user.id]);
  res.json({ message: "Saved" });
});
app.delete("/api/moments/:id/save", requireAuth, async (req, res) => {
  await query("DELETE FROM MomentSaves WHERE momentId = $1 AND userId = $2", [Number(req.params.id), req.user.id]);
  res.json({ message: "Unsaved" });
});
app.get("/api/moments/:id/comments", requireAuth, async (req, res) => {
  const result = await query(
    `SELECT c.id, c.content, c.createdAt, u.username, u.id AS userId FROM MomentComments c
     JOIN Users u ON u.id = c.userId WHERE c.momentId = $1 ORDER BY c.createdAt ASC`,
    [Number(req.params.id)]
  );
  res.json({ comments: result.rows.map((r) => ({ id: r.id, content: r.content, createdAt: r.createdat, username: r.username, userId: r.userid })) });
});
app.post("/api/moments/:id/comments", requireAuth, async (req, res) => {
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: "content is required" });
  await query("INSERT INTO MomentComments (momentId, userId, content) VALUES ($1,$2,$3)", [Number(req.params.id), req.user.id, content]);
  res.json({ message: "Commented" });
});
app.post("/api/moments/:id/report", requireAuth, async (req, res) => {
  const { reason } = req.body;
  await query("INSERT INTO MessageReports (messageId, reportedBy, reason) VALUES (NULL,$1,$2)", [req.user.id, `Moment #${req.params.id}: ${reason || "Not specified"}`]);
  res.json({ message: "Reported. Our team will review this." });
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
