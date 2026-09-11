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
    isReseller: isResellerEmail(row.email),
    isAdmin: isAdminEmail(row.email),
    verifiedType: row.verifiedtype || "none",
    dbCode: row.dbcode,
  };
}

// The fixed 7-day task ladder (also used by /api/tasks below)
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
      // Kick off the 7-Day Welcome Task timer the first time this account verifies a phone.
      await query("UPDATE Users SET taskStartAt = now() WHERE id = $1 AND taskStartAt IS NULL", [userId]);
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

// Bank-transfer withdrawal is intentionally NOT offered - per spec, diamonds
// can only be cashed out through a Reseller (see /api/wallet/reseller/sell).
// This 410 keeps the route documented instead of just disappearing.
app.post("/api/wallet/withdraw", requireAuth, async (req, res) => {
  res.status(410).json({ error: "Direct withdrawal isn't available. Sell your diamonds to a Reseller instead." });
});

// ---- EXCHANGE: Coins <-> Diamonds, min 10,000, user keeps 2/3 ----------
app.post("/api/wallet/exchange", requireAuth, async (req, res) => {
  const { direction, amount } = req.body; // direction: 'coinsToDiamonds' | 'diamondsToCoins'
  if (!["coinsToDiamonds", "diamondsToCoins"].includes(direction)) return res.status(400).json({ error: "direction must be coinsToDiamonds or diamondsToCoins" });
  if (!Number.isInteger(amount) || amount < 10000) return res.status(400).json({ error: "Minimum exchange amount is 10,000" });
  const walletResult = await query("SELECT coinBalance, diamondBalance FROM Wallets WHERE userId = $1", [req.user.id]);
  const wallet = walletResult.rows[0];
  const sourceBalance = direction === "coinsToDiamonds" ? wallet.coinbalance : wallet.diamondbalance;
  if (sourceBalance < amount) return res.status(400).json({ error: "Insufficient balance for this exchange" });
  const userAmount = Math.floor((amount * 2) / 3);
  const companyAmount = amount - userAmount;
  if (direction === "coinsToDiamonds") {
    await query("UPDATE Wallets SET coinBalance = coinBalance - $1, diamondBalance = diamondBalance + $2, updatedAt = now() WHERE userId = $3", [
      amount, userAmount, req.user.id,
    ]);
    await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1,'exchange_coins_out',$2,$3)", [
      req.user.id, -amount, JSON.stringify({ note: "Exchanged to Diamonds", companyFee: companyAmount }),
    ]);
    await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1,'exchange_diamonds_in',$2,$3)", [
      req.user.id, userAmount, JSON.stringify({ note: "Exchanged from Coins" }),
    ]);
  } else {
    await query("UPDATE Wallets SET diamondBalance = diamondBalance - $1, coinBalance = coinBalance + $2, updatedAt = now() WHERE userId = $3", [
      amount, userAmount, req.user.id,
    ]);
    await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1,'exchange_diamonds_out',$2,$3)", [
      req.user.id, -amount, JSON.stringify({ note: "Exchanged to Coins", companyFee: companyAmount }),
    ]);
    await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1,'exchange_coins_in',$2,$3)", [
      req.user.id, userAmount, JSON.stringify({ note: "Exchanged from Diamonds" }),
    ]);
  }
  res.json({ message: `Exchanged ${amount.toLocaleString()} -> you received ${userAmount.toLocaleString()} (${companyAmount.toLocaleString()} company fee)`, userAmount, companyAmount });
});

// ---- RESELLER: Buy from Reseller / Sell to Reseller ---------------------
// Both create a pending request; a Reseller Panel (coming in a later phase)
// will approve or reject these. Selling deducts diamonds immediately per
// spec ("deduct from balance -> status pending"); buying only credits the
// balance once a reseller approves the request.
app.post("/api/wallet/reseller/sell", requireAuth, async (req, res) => {
  const { diamonds } = req.body;
  if (!Number.isInteger(diamonds) || diamonds <= 0) return res.status(400).json({ error: "diamonds must be a positive integer" });
  const walletResult = await query("SELECT diamondBalance FROM Wallets WHERE userId = $1", [req.user.id]);
  if (!walletResult.rows[0] || walletResult.rows[0].diamondbalance < diamonds) return res.status(400).json({ error: "Insufficient diamond balance" });
  await query("UPDATE Wallets SET diamondBalance = diamondBalance - $1, updatedAt = now() WHERE userId = $2", [diamonds, req.user.id]);
  await query("INSERT INTO Transactions (userId, type, amount, meta, status) VALUES ($1,'reseller_sell_diamonds',$2,$3,'pending')", [
    req.user.id, -diamonds, JSON.stringify({ note: "Awaiting Reseller approval - Reseller pays you outside the app" }),
  ]);
  res.json({ message: `Sell request for ${diamonds.toLocaleString()} diamonds submitted - pending Reseller approval` });
});
app.post("/api/wallet/reseller/buy", requireAuth, async (req, res) => {
  const { currency, amount } = req.body; // currency: 'coins' | 'diamonds'
  if (!["coins", "diamonds"].includes(currency)) return res.status(400).json({ error: "currency must be coins or diamonds" });
  if (!Number.isInteger(amount) || amount <= 0) return res.status(400).json({ error: "amount must be a positive integer" });
  const type = currency === "coins" ? "reseller_buy_coins" : "reseller_buy_diamonds";
  await query("INSERT INTO Transactions (userId, type, amount, meta, status) VALUES ($1,$2,$3,$4,'pending')", [
    req.user.id, type, amount, JSON.stringify({ note: "Awaiting Reseller approval" }),
  ]);
  res.json({ message: `Buy request for ${amount.toLocaleString()} ${currency} submitted - pending Reseller approval` });
});

// ---- WALLET HISTORY: Coin tab / Diamond tab ------------------------------
const COIN_TX_TYPES = ["purchase", "gift_sent", "task_reward", "vip_daily_claim", "exchange_coins_out", "exchange_coins_in", "reseller_buy_coins", "game_win", "game_loss"];
const DIAMOND_TX_TYPES = ["gift_received", "withdrawal", "exchange_diamonds_out", "exchange_diamonds_in", "reseller_sell_diamonds", "reseller_buy_diamonds"];
app.get("/api/wallet/history", requireAuth, async (req, res) => {
  const currency = req.query.currency === "diamonds" ? "diamonds" : "coins";
  const types = currency === "diamonds" ? DIAMOND_TX_TYPES : COIN_TX_TYPES;
  const result = await query(
    "SELECT id, type, amount, status, createdAt FROM Transactions WHERE userId = $1 AND type = ANY($2) ORDER BY createdAt DESC LIMIT 100",
    [req.user.id, types]
  );
  res.json({
    history: result.rows.map((r) => ({ id: r.id, type: r.type, amount: r.amount, status: r.status, createdAt: r.createdat })),
  });
});

// =================================================================
// RESELLER PANEL
// =================================================================
// Reseller status is decided purely by email match against RESELLER_EMAILS
// (comma-separated), set as an environment variable on Render. No DB flag,
// no admin login yet - see the note on the admin-approve endpoints below.
function resellerEmailList() {
  return (process.env.RESELLER_EMAILS || "").split(",").map((e) => e.trim().toLowerCase()).filter(Boolean);
}
function isResellerEmail(email) {
  return resellerEmailList().includes((email || "").toLowerCase());
}
function requireReseller(req, res, next) {
  if (!isResellerEmail(req.user.email)) return res.status(403).json({ error: "Reseller access only" });
  next();
}

// ---- ADMIN (same email-allowlist pattern as Reseller) --------------------
function adminEmailList() {
  return (process.env.ADMIN_EMAILS || "").split(",").map((e) => e.trim().toLowerCase()).filter(Boolean);
}
function isAdminEmail(email) {
  return adminEmailList().includes((email || "").toLowerCase());
}
function requireAdmin(req, res, next) {
  if (!isAdminEmail(req.user.email)) return res.status(403).json({ error: "Admin access only" });
  next();
}
app.get("/api/admin/status", requireAuth, async (req, res) => {
  res.json({ isAdmin: isAdminEmail(req.user.email) });
});

app.get("/api/reseller/status", requireAuth, async (req, res) => {
  res.json({ isReseller: isResellerEmail(req.user.email) });
});

const RESELLER_SELL_TO_COMPANY_MIN_USD = 100;
const RESELLER_BUY_FROM_COMPANY_MIN_USD = 100;
const DIAMONDS_PER_USD_SELL_TO_COMPANY = 100000; // 10,000,000 diamonds = $100
const COINS_PER_USD_BUY_FROM_COMPANY = 110000; // $100 = 11,000,000 coins

// ---- 1. SELL TO COMPANY (diamonds only) ----------------------------------
app.post("/api/reseller/sell-to-company", requireAuth, requireReseller, async (req, res) => {
  const { diamonds, payoutInfo } = req.body;
  if (!Number.isInteger(diamonds) || diamonds <= 0) return res.status(400).json({ error: "diamonds must be a positive integer" });
  const usdAmount = diamonds / DIAMONDS_PER_USD_SELL_TO_COMPANY;
  if (usdAmount < RESELLER_SELL_TO_COMPANY_MIN_USD) return res.status(400).json({ error: `Minimum sell is $${RESELLER_SELL_TO_COMPANY_MIN_USD} (${(RESELLER_SELL_TO_COMPANY_MIN_USD * DIAMONDS_PER_USD_SELL_TO_COMPANY).toLocaleString()} diamonds)` });
  if (!payoutInfo || (!payoutInfo.trc20Address && !(payoutInfo.accountNumber && payoutInfo.accountName && payoutInfo.bankName))) {
    return res.status(400).json({ error: "Provide either a TRC20 address or account number, account name, and bank name" });
  }
  const walletResult = await query("SELECT diamondBalance FROM Wallets WHERE userId = $1", [req.user.id]);
  if (!walletResult.rows[0] || walletResult.rows[0].diamondbalance < diamonds) return res.status(400).json({ error: "Insufficient diamond balance" });
  await query("UPDATE Wallets SET diamondBalance = diamondBalance - $1, updatedAt = now() WHERE userId = $2", [diamonds, req.user.id]);
  await query(
    "INSERT INTO ResellerDeals (dealType, resellerId, assetType, amount, usdAmount, payoutInfo, status) VALUES ('sell_diamonds_to_company',$1,'diamonds',$2,$3,$4,'pending')",
    [req.user.id, diamonds, usdAmount, JSON.stringify(payoutInfo)]
  );
  await query("INSERT INTO Transactions (userId, type, amount, meta, status) VALUES ($1,'reseller_sell_diamonds',$2,$3,'pending')", [
    req.user.id, -diamonds, JSON.stringify({ note: "Sell to Company - awaiting Admin approval", usdAmount }),
  ]);
  res.json({ message: `Sell request for ${diamonds.toLocaleString()} diamonds (≈$${usdAmount.toFixed(2)}) submitted - pending Admin approval` });
});

// ---- 2. BUY FROM COMPANY (coins only, min $100) --------------------------
app.post("/api/reseller/buy-from-company", requireAuth, requireReseller, async (req, res) => {
  const { usdAmount } = req.body;
  if (!usdAmount || usdAmount < RESELLER_BUY_FROM_COMPANY_MIN_USD) return res.status(400).json({ error: `Minimum purchase is $${RESELLER_BUY_FROM_COMPANY_MIN_USD}` });
  const coins = Math.round(usdAmount * COINS_PER_USD_BUY_FROM_COMPANY);
  await query(
    "INSERT INTO ResellerDeals (dealType, resellerId, assetType, amount, usdAmount, status) VALUES ('buy_coins_from_company',$1,'coins',$2,$3,'pending')",
    [req.user.id, coins, usdAmount]
  );
  await query("INSERT INTO Transactions (userId, type, amount, meta, status) VALUES ($1,'reseller_buy_coins',$2,$3,'pending')", [
    req.user.id, coins, JSON.stringify({ note: "Buy from Company - awaiting Admin approval", usdAmount }),
  ]);
  res.json({ message: `Buy request for ${coins.toLocaleString()} coins (≈$${usdAmount}) submitted - pending Admin approval` });
});

// ---- 3. BUY FROM USERS (diamonds only, two-sided) -------------------------
// Either side can start it; the OTHER side has to respond before anything moves.
app.post("/api/reseller/buy-diamonds-from-user", requireAuth, async (req, res) => {
  const { resellerId, diamonds } = req.body;
  if (!Number.isInteger(diamonds) || diamonds <= 0) return res.status(400).json({ error: "diamonds must be a positive integer" });
  if (!isResellerEmail((await query("SELECT email FROM Users WHERE id = $1", [resellerId])).rows[0]?.email)) {
    return res.status(400).json({ error: "That user isn't a Reseller" });
  }
  const walletResult = await query("SELECT diamondBalance FROM Wallets WHERE userId = $1", [req.user.id]);
  if (!walletResult.rows[0] || walletResult.rows[0].diamondbalance < diamonds) return res.status(400).json({ error: "Insufficient diamond balance" });
  const result = await query(
    "INSERT INTO ResellerDeals (dealType, resellerId, counterpartyUserId, initiatedBy, assetType, amount, status) VALUES ('buy_diamonds_from_user',$1,$2,$2,'diamonds',$3,'pending') RETURNING id",
    [resellerId, req.user.id, diamonds]
  );
  await query("INSERT INTO SystemMessages (userId, type, content) VALUES ($1,'withdraw','A user wants to sell you diamonds. Review it in your Reseller Panel.')", [resellerId]);
  res.json({ message: "Request sent to the Reseller - pending their approval", dealId: result.rows[0].id });
});
app.post("/api/reseller/propose-buy-from-user", requireAuth, requireReseller, async (req, res) => {
  const { counterpartyUserId, diamonds } = req.body;
  if (!Number.isInteger(diamonds) || diamonds <= 0) return res.status(400).json({ error: "diamonds must be a positive integer" });
  const targetResult = await query("SELECT diamondBalance FROM Wallets WHERE userId = $1", [counterpartyUserId]);
  if (!targetResult.rows[0]) return res.status(404).json({ error: "User not found" });
  const result = await query(
    "INSERT INTO ResellerDeals (dealType, resellerId, counterpartyUserId, initiatedBy, assetType, amount, status) VALUES ('buy_diamonds_from_user',$1,$2,$1,'diamonds',$3,'pending') RETURNING id",
    [req.user.id, counterpartyUserId, diamonds]
  );
  await query("INSERT INTO SystemMessages (userId, type, content) VALUES ($1,'withdraw','A Reseller wants to buy your diamonds. Review it in Wallet > Reseller.')", [counterpartyUserId]);
  res.json({ message: "Offer sent to the user - pending their response", dealId: result.rows[0].id });
});

// ---- 4. SELL TO USER (coins only, instant, no approval needed) -----------
app.post("/api/reseller/sell-coins-to-user", requireAuth, requireReseller, async (req, res) => {
  const { userId, coins } = req.body;
  if (!Number.isInteger(coins) || coins <= 0) return res.status(400).json({ error: "coins must be a positive integer" });
  const walletResult = await query("SELECT coinBalance FROM Wallets WHERE userId = $1", [req.user.id]);
  if (!walletResult.rows[0] || walletResult.rows[0].coinbalance < coins) return res.status(400).json({ error: "Insufficient coin balance" });
  const targetResult = await query("SELECT id FROM Users WHERE id = $1", [userId]);
  if (targetResult.rows.length === 0) return res.status(404).json({ error: "User not found" });
  await query("UPDATE Wallets SET coinBalance = coinBalance - $1, updatedAt = now() WHERE userId = $2", [coins, req.user.id]);
  await query("UPDATE Wallets SET coinBalance = coinBalance + $1, updatedAt = now() WHERE userId = $2", [coins, userId]);
  await query(
    "INSERT INTO ResellerDeals (dealType, resellerId, counterpartyUserId, initiatedBy, assetType, amount, status, resolvedAt) VALUES ('sell_coins_to_user',$1,$2,$1,'coins',$3,'approved',now())",
    [req.user.id, userId, coins]
  );
  await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1,'reseller_buy_coins',$2,$3)", [
    userId, coins, JSON.stringify({ note: "Bought from Reseller", resellerId: req.user.id }),
  ]);
  await query("INSERT INTO SystemMessages (userId, type, content) VALUES ($1,'recharge',$2)", [
    userId, `A Reseller sent you ${coins.toLocaleString()} coins.`,
  ]);
  res.json({ message: `Sent ${coins.toLocaleString()} coins to the user` });
});

// ---- Respond to a two-sided "Buy from Users" deal --------------------
app.post("/api/reseller/deals/:id/respond", requireAuth, async (req, res) => {
  const { accept } = req.body;
  const dealResult = await query("SELECT * FROM ResellerDeals WHERE id = $1 AND status = 'pending'", [Number(req.params.id)]);
  if (dealResult.rows.length === 0) return res.status(404).json({ error: "Deal not found or already resolved" });
  const deal = dealResult.rows[0];
  if (![deal.resellerid, deal.counterpartyuserid].includes(req.user.id) || deal.initiatedby === req.user.id) {
    return res.status(403).json({ error: "Only the other party can respond to this deal" });
  }
  if (!accept) {
    await query("UPDATE ResellerDeals SET status = 'rejected', resolvedAt = now() WHERE id = $1", [deal.id]);
    return res.json({ message: "Deal rejected" });
  }
  const walletResult = await query("SELECT diamondBalance FROM Wallets WHERE userId = $1", [deal.counterpartyuserid]);
  if (!walletResult.rows[0] || walletResult.rows[0].diamondbalance < deal.amount) {
    await query("UPDATE ResellerDeals SET status = 'rejected', resolvedAt = now() WHERE id = $1", [deal.id]);
    return res.status(400).json({ error: "The user no longer has enough diamonds - deal rejected" });
  }
  await query("UPDATE Wallets SET diamondBalance = diamondBalance - $1, updatedAt = now() WHERE userId = $2", [deal.amount, deal.counterpartyuserid]);
  await query("UPDATE Wallets SET diamondBalance = diamondBalance + $1, updatedAt = now() WHERE userId = $2", [deal.amount, deal.resellerid]);
  await query("UPDATE ResellerDeals SET status = 'approved', resolvedAt = now() WHERE id = $1", [deal.id]);
  await query("INSERT INTO Transactions (userId, type, amount, meta, status) VALUES ($1,'reseller_sell_diamonds',$2,$3,'completed')", [
    deal.counterpartyuserid, -deal.amount, JSON.stringify({ note: "Sold to Reseller", resellerId: deal.resellerid }),
  ]);
  res.json({ message: `Deal completed: ${Number(deal.amount).toLocaleString()} diamonds transferred` });
});

app.get("/api/reseller/deals", requireAuth, requireReseller, async (req, res) => {
  const filter = req.query.filter || "all";
  let where = "resellerId = $1";
  const params = [req.user.id];
  if (filter === "buy") where += " AND dealType IN ('buy_coins_from_company','buy_diamonds_from_user')";
  if (filter === "sell") where += " AND dealType IN ('sell_diamonds_to_company','sell_coins_to_user')";
  if (filter === "pending") where += " AND status = 'pending'";
  if (filter === "approved") where += " AND status = 'approved'";
  const result = await query(`SELECT * FROM ResellerDeals WHERE ${where} ORDER BY createdAt DESC LIMIT 100`, params);
  res.json({ deals: result.rows.map(mapResellerDeal) });
});
app.get("/api/reseller/deals/incoming", requireAuth, requireReseller, async (req, res) => {
  const result = await query(
    "SELECT * FROM ResellerDeals WHERE resellerId = $1 AND status = 'pending' AND initiatedBy != $1 ORDER BY createdAt DESC",
    [req.user.id]
  );
  res.json({ deals: result.rows.map(mapResellerDeal) });
});
function mapResellerDeal(r) {
  return {
    id: r.id, dealType: r.dealtype, resellerId: r.resellerid, counterpartyUserId: r.counterpartyuserid,
    initiatedBy: r.initiatedby, assetType: r.assettype, amount: Number(r.amount), usdAmount: r.usdamount ? Number(r.usdamount) : null,
    payoutInfo: r.payoutinfo, status: r.status, createdAt: r.createdat, resolvedAt: r.resolvedat,
  };
}
app.get("/api/reseller/search", requireAuth, async (req, res) => {
  const q = (req.query.q || "").trim();
  const emails = resellerEmailList();
  if (emails.length === 0) return res.json({ resellers: [] });
  const result = await query(
    `SELECT id, username, amanaId, prettyId FROM Users WHERE email = ANY($1) AND (username ILIKE $2 OR amanaId ILIKE $2 OR prettyId ILIKE $2) LIMIT 20`,
    [emails, `%${q}%`]
  );
  res.json({ resellers: result.rows.map((r) => ({ id: r.id, username: r.username, amanaId: r.amanaid, prettyId: r.prettyid })) });
});

// Admin approval for company-facing deals - no admin login system exists
// yet, so this is intentionally left open for now (see VIP/Level tier PATCH
// endpoints for the same note). Lock this down before public launch.
app.get("/api/reseller/admin/pending", requireAuth, requireAdmin, async (req, res) => {
  const result = await query(
    `SELECT rd.*, u.username, u.email FROM ResellerDeals rd JOIN Users u ON u.id = rd.resellerId
     WHERE rd.status = 'pending' AND rd.dealType IN ('sell_diamonds_to_company','buy_coins_from_company') ORDER BY rd.createdAt ASC`
  );
  res.json({ deals: result.rows.map((r) => ({ ...mapResellerDeal(r), resellerUsername: r.username, resellerEmail: r.email })) });
});
app.post("/api/reseller/admin/deals/:id/approve", requireAuth, requireAdmin, async (req, res) => {
  const { approve } = req.body;
  const dealResult = await query("SELECT * FROM ResellerDeals WHERE id = $1 AND status = 'pending'", [Number(req.params.id)]);
  if (dealResult.rows.length === 0) return res.status(404).json({ error: "Deal not found or already resolved" });
  const deal = dealResult.rows[0];
  if (!approve) {
    await query("UPDATE ResellerDeals SET status = 'rejected', resolvedAt = now() WHERE id = $1", [deal.id]);
    if (deal.dealtype === "sell_diamonds_to_company") {
      // refund the diamonds that were deducted up front
      await query("UPDATE Wallets SET diamondBalance = diamondBalance + $1 WHERE userId = $2", [deal.amount, deal.resellerid]);
    }
    return res.json({ message: "Deal rejected" });
  }
  await query("UPDATE ResellerDeals SET status = 'approved', resolvedAt = now() WHERE id = $1", [deal.id]);
  if (deal.dealtype === "buy_coins_from_company") {
    await query("UPDATE Wallets SET coinBalance = coinBalance + $1, updatedAt = now() WHERE userId = $2", [deal.amount, deal.resellerid]);
  }
  // sell_diamonds_to_company: diamonds were already deducted at request time; approval just confirms the payout was sent outside the app.
  res.json({ message: "Deal approved" });
});

// =================================================================
// GIFTS - catalog + core send logic (reused by the socket handler below)
// =================================================================
function giftAnimationTier(coinCost) {
  if (coinCost >= 1000000) return "crown"; // full-screen Golden Crown explosion + VIP sound
  if (coinCost >= 50000) return "house"; // house flies in animation
  return "medium";
}
function mapGift(g) {
  return {
    id: g.id, name: g.name, icon: g.icon, coinCost: g.coincost, category: g.category,
    receiverSplitPct: g.receiversplitpct, animationTier: giftAnimationTier(g.coincost),
    isCustom: g.iscustom, minVipLevel: g.minviplevel,
  };
}
app.get("/api/gifts", async (req, res) => {
  const result = await query("SELECT * FROM Gifts WHERE active = TRUE AND (isCustom = FALSE OR customStatus = 'approved') ORDER BY coinCost ASC");
  res.json({ gifts: result.rows.map(mapGift) });
});
// Same catalog, grouped by category - what the Gift Shop UI actually renders.
app.get("/api/gifts/shop", requireAuth, async (req, res) => {
  const result = await query(
    "SELECT * FROM Gifts WHERE active = TRUE AND ((isCustom = FALSE) OR (isCustom = TRUE AND (customStatus = 'approved' OR requestedByUserId = $1))) ORDER BY category, coinCost ASC",
    [req.user.id]
  );
  const grouped = {};
  for (const row of result.rows) {
    const g = mapGift(row);
    if (!grouped[g.category]) grouped[g.category] = [];
    grouped[g.category].push(g);
  }
  res.json({ categories: grouped });
});

// ---- Custom Gift: user request (pays now, Admin approves) --------------
app.post("/api/gifts/custom/request", requireAuth, async (req, res) => {
  const { name, price, icon, imageUrl } = req.body;
  if (!name || !Number.isInteger(price) || price < 50000 || price > 2000000) {
    return res.status(400).json({ error: "Price must be between 50,000 and 2,000,000 coins" });
  }
  const walletResult = await query("SELECT coinBalance FROM Wallets WHERE userId = $1", [req.user.id]);
  if (!walletResult.rows[0] || walletResult.rows[0].coinbalance < price) return res.status(400).json({ error: "Insufficient coin balance" });
  await query("UPDATE Wallets SET coinBalance = coinBalance - $1, updatedAt = now() WHERE userId = $2", [price, req.user.id]);
  await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1,'purchase',$2,$3)", [
    req.user.id, -price, JSON.stringify({ note: "Custom gift request", giftName: name }),
  ]);
  const result = await query(
    `INSERT INTO Gifts (name, icon, coinCost, category, isCustom, requestedByUserId, customStatus, active)
     VALUES ($1,$2,$3,'CUSTOM',TRUE,$4,'pending',FALSE) RETURNING id`,
    [name, icon || imageUrl || "🎁", price, req.user.id]
  );
  res.json({ message: "Custom gift submitted for review - you already paid, it'll be usable once approved", id: result.rows[0].id });
});
app.get("/api/gifts/custom/mine", requireAuth, async (req, res) => {
  const result = await query("SELECT * FROM Gifts WHERE isCustom = TRUE AND requestedByUserId = $1 ORDER BY id DESC", [req.user.id]);
  res.json({ requests: result.rows.map((g) => ({ id: g.id, name: g.name, coinCost: g.coincost, status: g.customstatus })) });
});
app.get("/api/admin/gifts/custom-requests", requireAuth, requireAdmin, async (req, res) => {
  const result = await query(
    `SELECT g.*, u.username FROM Gifts g JOIN Users u ON u.id = g.requestedByUserId WHERE g.isCustom = TRUE AND g.customStatus = 'pending' ORDER BY g.id ASC`
  );
  res.json({ requests: result.rows.map((g) => ({ id: g.id, name: g.name, coinCost: g.coincost, icon: g.icon, username: g.username })) });
});
app.post("/api/admin/gifts/custom-requests/:id/respond", requireAuth, requireAdmin, async (req, res) => {
  const { approve } = req.body;
  const giftResult = await query("SELECT * FROM Gifts WHERE id = $1 AND isCustom = TRUE AND customStatus = 'pending'", [Number(req.params.id)]);
  if (giftResult.rows.length === 0) return res.status(404).json({ error: "Request not found" });
  const gift = giftResult.rows[0];
  if (approve) {
    await query("UPDATE Gifts SET customStatus = 'approved', active = TRUE WHERE id = $1", [gift.id]);
  } else {
    await query("UPDATE Gifts SET customStatus = 'rejected' WHERE id = $1", [gift.id]);
    // Refund the request fee since it was charged up front.
    await query("UPDATE Wallets SET coinBalance = coinBalance + $1, updatedAt = now() WHERE userId = $2", [gift.coincost, gift.requestedbyuserid]);
    await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1,'purchase',$2,$3)", [
      gift.requestedbyuserid, gift.coincost, JSON.stringify({ note: "Custom gift request rejected - refunded" }),
    ]);
  }
  await query("INSERT INTO SystemMessages (userId, type, content) VALUES ($1,'task',$2)", [
    gift.requestedbyuserid, approve ? `Your custom gift "${gift.name}" was approved!` : `Your custom gift "${gift.name}" was rejected - refunded.`,
  ]);
  res.json({ message: approve ? "Approved" : "Rejected and refunded" });
});
// Admin sends a gift directly from the panel - creates it active immediately, usable by everyone.
app.post("/api/admin/gifts/custom-send", requireAuth, requireAdmin, async (req, res) => {
  const { name, price, icon } = req.body;
  if (!name || !Number.isInteger(price)) return res.status(400).json({ error: "name and price are required" });
  const result = await query(
    "INSERT INTO Gifts (name, icon, coinCost, category, isCustom, customStatus, active) VALUES ($1,$2,$3,'CUSTOM',TRUE,'approved',TRUE) RETURNING id",
    [name, icon || "🎁", price]
  );
  res.json({ message: "Custom gift added to the shop", id: result.rows[0].id });
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

  // Commission is fixed per gift (Normal Gifts = 60% receiver / 40% admin).
  const hostShare = Math.round(gift.coincost * (gift.receiversplitpct / 100));

  await query("UPDATE Wallets SET coinBalance = coinBalance - $1, updatedAt = now() WHERE userId = $2", [gift.coincost, senderId]);
  await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1, 'gift_sent', $2, $3)", [
    senderId,
    -gift.coincost,
    JSON.stringify({ streamId, giftId, giftName: gift.name, toUserId: stream.hostid }),
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
  await creditFamilyContribution(senderId, gift.coincost, `in Room ${streamId}`);

  return { hostId: stream.hostid, giftName: gift.name, icon: gift.icon, coinCost: gift.coincost, hostShare };
}

app.post("/api/gifts/send", requireAuth, async (req, res) => {
  try {
    const { streamId, giftId } = req.body;
    if (!streamId || !giftId) return res.status(400).json({ error: "streamId and giftId are required" });
    const result = await sendGiftOrSpin({ senderId: req.user.id, streamId, giftId });
    res.json({ message: "Gift sent", ...result });
  } catch (err) {
    res.status(400).json({ error: err.message || "Failed to send gift" });
  }
});

// =================================================================
// LUCKY WHEEL - RTP mini-game, triggered when a gift's category is
// 'LUCKY WHEEL' (the 4 Animal-tier gifts). Sender's stake (coinCost) is
// wagered; a weighted-random multiplier decides the payout, which the
// receiver (stream host) gets a % of as diamonds. Admin never wagers its
// own coins - reservePool just tracks (stake - payout) every spin, so it
// only ever reflects what was actually collected vs paid out.
// =================================================================
async function getLuckyWheelConfig() {
  const [settingsRes, outcomesRes] = await Promise.all([
    query("SELECT * FROM LuckyWheelSettings WHERE id = 1"),
    query("SELECT * FROM LuckyWheelOutcomes ORDER BY sortOrder ASC"),
  ]);
  return { settings: settingsRes.rows[0], outcomes: outcomesRes.rows };
}

function pickWeightedOutcome(outcomes) {
  const total = outcomes.reduce((s, o) => s + Number(o.weightpct), 0);
  let r = Math.random() * total;
  for (const o of outcomes) {
    r -= Number(o.weightpct);
    if (r <= 0) return o;
  }
  return outcomes[outcomes.length - 1];
}

async function spinLuckyWheel({ senderId, streamId, giftId }) {
  const giftResult = await query("SELECT * FROM Gifts WHERE id = $1", [giftId]);
  if (giftResult.rows.length === 0) throw new Error("Gift not found");
  const gift = giftResult.rows[0];

  const streamResult = await query("SELECT * FROM LiveStreams WHERE id = $1", [streamId]);
  if (streamResult.rows.length === 0) throw new Error("Stream not found");
  const stream = streamResult.rows[0];

  const walletResult = await query("SELECT * FROM Wallets WHERE userId = $1", [senderId]);
  const senderWallet = walletResult.rows[0];
  const stake = gift.coincost;
  if (!senderWallet || senderWallet.coinbalance < stake) throw new Error("Insufficient coin balance");

  const { settings, outcomes } = await getLuckyWheelConfig();
  if (outcomes.length === 0) throw new Error("Lucky Wheel isn't configured yet");

  // Pity system: after maxLossStreak straight sub-1x spins, force the next
  // spin to land on a break-even-or-better outcome (if any are configured).
  let pool = outcomes;
  if (senderWallet.luckylossstreak >= settings.maxlossstreak) {
    const nonLoss = outcomes.filter((o) => Number(o.multiplier) >= 1);
    if (nonLoss.length > 0) pool = nonLoss;
  }
  const outcome = pickWeightedOutcome(pool);
  const multiplier = Number(outcome.multiplier);
  const payout = Math.round(stake * multiplier);
  const receiverDiamonds = Math.round(payout * (settings.receiversplitpct / 100));
  const newStreak = multiplier < 1 ? senderWallet.luckylossstreak + 1 : 0;

  // Sender always pays the stake - the "win" flows to the receiver, same as
  // a normal gift. This is logged as game_loss (an existing tx type) since
  // the sender never gets coins back regardless of the spin's outcome.
  await query(
    "UPDATE Wallets SET coinBalance = coinBalance - $1, luckyLossStreak = $2, updatedAt = now() WHERE userId = $3",
    [stake, newStreak, senderId]
  );
  await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1,'game_loss',$2,$3)", [
    senderId, -stake,
    JSON.stringify({ streamId, giftId, giftName: gift.name, toUserId: stream.hostid, luckyWheel: true, multiplier }),
  ]);

  if (receiverDiamonds > 0) {
    await query("UPDATE Wallets SET diamondBalance = diamondBalance + $1, updatedAt = now() WHERE userId = $2", [receiverDiamonds, stream.hostid]);
    await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1,'gift_received',$2,$3)", [
      stream.hostid, receiverDiamonds,
      JSON.stringify({ streamId, giftId, giftName: gift.name, fromUserId: senderId, luckyWheel: true, multiplier }),
    ]);
  }

  await query("UPDATE LiveStreams SET totalCoinsEarned = totalCoinsEarned + $1 WHERE id = $2", [stake, streamId]);
  // reservePool moves by exactly (stake - payout) - never touched anywhere else,
  // so it always reflects real collected-vs-paid-out, nothing more.
  await query("UPDATE LuckyWheelSettings SET reservePool = reservePool + $1, updatedAt = now() WHERE id = 1", [stake - payout]);

  return {
    hostId: stream.hostid, giftName: gift.name, icon: gift.icon, coinCost: stake,
    multiplier, payout, receiverDiamonds, isLuckyWheel: true,
  };
}

// Routes a gift send to the Lucky Wheel spin if that's what category the
// gift belongs to, otherwise the normal fixed-split gift flow. Both the
// REST endpoint and the socket handler go through this single entry point.
async function sendGiftOrSpin({ senderId, streamId, giftId }) {
  const giftResult = await query("SELECT category FROM Gifts WHERE id = $1", [giftId]);
  if (giftResult.rows.length === 0) throw new Error("Gift not found");
  if (giftResult.rows[0].category === "LUCKY WHEEL") {
    return spinLuckyWheel({ senderId, streamId, giftId });
  }
  return sendGift({ senderId, streamId, giftId });
}

// ---- Lucky Wheel admin config -------------------------------------------
app.get("/api/admin/lucky-wheel/config", requireAuth, requireAdmin, async (req, res) => {
  const { settings, outcomes } = await getLuckyWheelConfig();
  res.json({ settings, outcomes });
});
app.put("/api/admin/lucky-wheel/config", requireAuth, requireAdmin, async (req, res) => {
  const { targetRtp, receiverSplitPct, maxLossStreak, riskThresholdPct, outcomes } = req.body;
  const sets = [];
  const vals = [];
  const pushSet = (col, val) => { if (val !== undefined) { vals.push(val); sets.push(`${col} = $${vals.length}`); } };
  pushSet("targetRtp", targetRtp);
  pushSet("receiverSplitPct", receiverSplitPct);
  pushSet("maxLossStreak", maxLossStreak);
  pushSet("riskThresholdPct", riskThresholdPct);
  if (sets.length > 0) {
    await query(`UPDATE LuckyWheelSettings SET ${sets.join(", ")}, updatedAt = now() WHERE id = 1`, vals);
  }
  if (Array.isArray(outcomes)) {
    const weightSum = outcomes.reduce((s, o) => s + Number(o.weightPct || 0), 0);
    if (Math.abs(weightSum - 100) > 0.1) {
      return res.status(400).json({ error: `Weights must sum to 100 (currently ${weightSum.toFixed(2)})` });
    }
    await query("DELETE FROM LuckyWheelOutcomes");
    for (let i = 0; i < outcomes.length; i++) {
      await query("INSERT INTO LuckyWheelOutcomes (multiplier, weightPct, sortOrder) VALUES ($1,$2,$3)", [
        outcomes[i].multiplier, outcomes[i].weightPct, i,
      ]);
    }
  }
  res.json({ message: "Lucky Wheel config updated" });
});
app.get("/api/admin/lucky-wheel/reserve", requireAuth, requireAdmin, async (req, res) => {
  const r = await query("SELECT reservePool, riskThresholdPct, updatedAt FROM LuckyWheelSettings WHERE id = 1");
  res.json(r.rows[0]);
});
app.post("/api/admin/lucky-wheel/reserve/adjust", requireAuth, requireAdmin, async (req, res) => {
  const { delta } = req.body;
  if (!Number.isInteger(delta)) return res.status(400).json({ error: "delta must be an integer" });
  await query("UPDATE LuckyWheelSettings SET reservePool = reservePool + $1, updatedAt = now() WHERE id = 1", [delta]);
  const r = await query("SELECT reservePool FROM LuckyWheelSettings WHERE id = 1");
  res.json({ reservePool: r.rows[0].reservepool });
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
// NEW USER 7-DAY TASK SYSTEM
// =================================================================
async function getTaskDefinitions() {
  const r = await query("SELECT * FROM TaskDefinitions WHERE active = TRUE ORDER BY day ASC, orderInDay ASC");
  return r.rows;
}
const BONUS_KEY = "complete_all_7_days";

// Each entry returns the user's current progress count for that trackingKey.
// Manual tasks (mic-related, "enter a room") have no real signal to check
// yet, so they're completed only when the user taps the GO button.
async function getTaskProgressValue(userId, task, taskStartAt) {
  const since = taskStartAt || new Date(0);
  switch (task.trackingkey) {
    case "bind_phone": {
      const r = await query("SELECT phoneVerified FROM Users WHERE id = $1", [userId]);
      return r.rows[0].phoneverified ? 1 : 0;
    }
    case "complete_profile": {
      // No device photo-upload yet, so "profile complete" is judged by the
      // text fields that do exist: gender, bio, and country all filled in.
      const r = await query("SELECT gender, bio, country FROM Users WHERE id = $1", [userId]);
      const u = r.rows[0];
      return u.gender && u.bio && u.country ? 1 : 0;
    }
    case "create_room": {
      const r = await query("SELECT COUNT(*) FROM LiveStreams WHERE hostId = $1", [userId]);
      return Number(r.rows[0].count) > 0 ? 1 : 0;
    }
    case "receive_gift": {
      const r = await query("SELECT COUNT(*) FROM Transactions WHERE userId = $1 AND type = 'gift_received' AND createdAt >= $2", [userId, since]);
      return Number(r.rows[0].count) > 0 ? 1 : 0;
    }
    case "chat_3_people": {
      const r = await query(
        "SELECT COUNT(DISTINCT receiverId) FROM Messages WHERE senderId = $1 AND createdAt >= $2",
        [userId, since]
      );
      return Number(r.rows[0].count);
    }
    case "post_3_moments": {
      const r = await query("SELECT COUNT(*) FROM Moments WHERE userId = $1 AND createdAt >= $2", [userId, since]);
      return Number(r.rows[0].count);
    }
    case "like_3_moments": {
      const r = await query("SELECT COUNT(*) FROM MomentLikes WHERE userId = $1 AND createdAt >= $2", [userId, since]);
      return Number(r.rows[0].count);
    }
    case "comment_3_moments": {
      const r = await query("SELECT COUNT(*) FROM MomentComments WHERE userId = $1 AND createdAt >= $2", [userId, since]);
      return Number(r.rows[0].count);
    }
    case "become_verified_or_family_supervised": {
      const r = await query("SELECT verifiedType FROM Users WHERE id = $1", [userId]);
      return ["host", "agency", "db"].includes(r.rows[0].verifiedtype) ? 1 : 0;
    }
    case "join_family": {
      const r = await query("SELECT 1 FROM FamilyMembers WHERE userId = $1", [userId]);
      return r.rows.length > 0 ? 1 : 0;
    }
    case "send_gift_1": {
      const r = await query("SELECT COUNT(*) FROM Transactions WHERE userId = $1 AND type = 'gift_sent' AND createdAt >= $2", [userId, since]);
      return Number(r.rows[0].count) > 0 ? 1 : 0;
    }
    case "follow_5": {
      const r = await query("SELECT COUNT(*) FROM Follows WHERE followerId = $1 AND createdAt >= $2", [userId, since]);
      return Number(r.rows[0].count);
    }
    case "gift_self_1000": {
      const r = await query(
        "SELECT COALESCE(SUM(-amount),0) AS total FROM Transactions WHERE userId = $1 AND type = 'gift_sent' AND meta->>'toSelf' = 'true' AND createdAt >= $2",
        [userId, since]
      );
      return Number(r.rows[0].total);
    }
    case "recharge_50000": {
      const r = await query(
        "SELECT COALESCE(SUM(amount),0) AS total FROM Transactions WHERE userId = $1 AND type = 'purchase' AND amount > 0 AND createdAt >= $2",
        [userId, since]
      );
      return Number(r.rows[0].total);
    }
    case "send_level_2": {
      const totals = await getSendReceiveTotals(userId);
      const tiers = await getTiers("SendLevelTiers");
      return computeLevelStatus(totals.sent, tiers).level;
    }
    case "receive_from_3_diff": {
      const r = await query(
        "SELECT COUNT(DISTINCT meta->>'fromUserId') FROM Transactions WHERE userId = $1 AND type = 'gift_received' AND meta->>'fromUserId' IS NOT NULL AND createdAt >= $2",
        [userId, since]
      );
      return Number(r.rows[0].count);
    }
    case "send_to_3_diff": {
      const r = await query(
        "SELECT COUNT(DISTINCT meta->>'toUserId') FROM Transactions WHERE userId = $1 AND type = 'gift_sent' AND meta->>'toUserId' IS NOT NULL AND createdAt >= $2",
        [userId, since]
      );
      return Number(r.rows[0].count);
    }
    default:
      return 0; // manual tasks (enter_room, invite_mic_3, stay_mic_10min) - checked via manualDone instead
  }
}

app.get("/api/tasks", requireAuth, async (req, res) => {
  const enabled = await getAppSetting("newuser_task_enabled");
  if (enabled === false) return res.json({ enabled: false });
  const userResult = await query("SELECT taskStartAt FROM Users WHERE id = $1", [req.user.id]);
  const taskStartAt = userResult.rows[0].taskstartat;
  if (!taskStartAt) return res.json({ enabled: true, started: false });

  const defs = await getTaskDefinitions();
  const progressResult = await query("SELECT * FROM UserTaskProgress WHERE userId = $1", [req.user.id]);
  const progressMap = {};
  progressResult.rows.forEach((p) => { progressMap[p.taskdefid] = p; });

  const msElapsed = Date.now() - new Date(taskStartAt).getTime();
  const dayNumber = Math.min(7, Math.floor(msElapsed / (24 * 60 * 60 * 1000)) + 1);
  const msLeftInWindow = 7 * 24 * 60 * 60 * 1000 - msElapsed;

  const tasks = [];
  let allClaimed = defs.length > 0;
  for (const def of defs) {
    const progress = progressMap[def.id];
    const claimed = progress?.claimed || false;
    let current;
    if (def.manual) current = progress?.manualdone ? def.targetvalue : 0;
    else current = await getTaskProgressValue(req.user.id, def, taskStartAt);
    const done = current >= def.targetvalue;
    if (!claimed) allClaimed = false;
    tasks.push({
      id: def.id, day: def.day, order: def.orderinday, title: def.title, trackingKey: def.trackingkey,
      target: def.targetvalue, current: Math.min(current, def.targetvalue), done, claimed,
      manual: def.manual, rewardCoins: def.rewardcoins,
      rewardItem: def.rewarditemname ? { category: def.rewarditemcategory, name: def.rewarditemname, days: def.rewarditemdays } : null,
    });
  }
  const bonusResult = await query("SELECT value FROM AppSettings WHERE key = 'task_bonus_coins'");
  const bonusCoins = bonusResult.rows[0] ? Number(bonusResult.rows[0].value) : 20000;
  const bonusClaimedResult = await query(
    "SELECT 1 FROM Transactions WHERE userId = $1 AND type = 'task_reward' AND meta->>'bonus' = 'true'",
    [req.user.id]
  );

  res.json({
    enabled: true, started: true, dayNumber, msLeftInWindow: Math.max(0, msLeftInWindow),
    tasks, bonusCoins, bonusClaimed: bonusClaimedResult.rows.length > 0, allTasksDone: allClaimed,
  });
});

app.post("/api/tasks/:id/go", requireAuth, async (req, res) => {
  const def = (await query("SELECT * FROM TaskDefinitions WHERE id = $1 AND manual = TRUE", [Number(req.params.id)])).rows[0];
  if (!def) return res.status(404).json({ error: "Manual task not found" });
  await query(
    `INSERT INTO UserTaskProgress (userId, taskDefId, manualDone) VALUES ($1,$2,TRUE)
     ON CONFLICT (userId, taskDefId) DO UPDATE SET manualDone = TRUE`,
    [req.user.id, def.id]
  );
  res.json({ message: "Marked done" });
});

app.post("/api/tasks/:id/claim", requireAuth, async (req, res) => {
  const defResult = await query("SELECT * FROM TaskDefinitions WHERE id = $1 AND active = TRUE", [Number(req.params.id)]);
  if (defResult.rows.length === 0) return res.status(404).json({ error: "Task not found" });
  const def = defResult.rows[0];
  const userResult = await query("SELECT taskStartAt FROM Users WHERE id = $1", [req.user.id]);
  const taskStartAt = userResult.rows[0].taskstartat;
  if (!taskStartAt) return res.status(400).json({ error: "Your 7-Day Task hasn't started yet - verify your phone first" });

  const existing = await query("SELECT * FROM UserTaskProgress WHERE userId = $1 AND taskDefId = $2", [req.user.id, def.id]);
  if (existing.rows[0]?.claimed) return res.status(400).json({ error: "Already claimed" });

  const current = def.manual
    ? (existing.rows[0]?.manualdone ? def.targetvalue : 0)
    : await getTaskProgressValue(req.user.id, def, taskStartAt);
  if (current < def.targetvalue) return res.status(400).json({ error: "Not completed yet" });

  await query(
    `INSERT INTO UserTaskProgress (userId, taskDefId, claimed, claimedAt) VALUES ($1,$2,TRUE,now())
     ON CONFLICT (userId, taskDefId) DO UPDATE SET claimed = TRUE, claimedAt = now()`,
    [req.user.id, def.id]
  );
  if (def.rewardcoins > 0) {
    await query("UPDATE Wallets SET coinBalance = coinBalance + $1, updatedAt = now() WHERE userId = $2", [def.rewardcoins, req.user.id]);
    await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1,'task_reward',$2,$3)", [
      req.user.id, def.rewardcoins, JSON.stringify({ day: def.day, task: def.trackingkey }),
    ]);
  }
  let grantedItem = null;
  if (def.rewarditemname) {
    const itemResult = await query("SELECT id FROM StoreItems WHERE name = $1", [def.rewarditemname]);
    if (itemResult.rows.length > 0) {
      const itemId = itemResult.rows[0].id;
      await query(
        `INSERT INTO UserInventory (userId, itemId, expiresAt) VALUES ($1,$2, now() + $3::interval)
         ON CONFLICT (userId, itemId) DO UPDATE SET expiresAt = GREATEST(UserInventory.expiresAt, now()) + $3::interval`,
        [req.user.id, itemId, `${def.rewarditemdays} days`]
      );
      grantedItem = def.rewarditemname;
    }
  }
  await query("INSERT INTO SystemMessages (userId, type, content) VALUES ($1,'task',$2)", [
    req.user.id, `Task complete: ${def.title}! ${def.rewardcoins > 0 ? `+${def.rewardcoins.toLocaleString()} coins. ` : ""}${grantedItem ? `${grantedItem} (${def.rewarditemdays} days) added to Dress Up.` : ""}`,
  ]);

  // Check the all-7-days completion bonus (only awarded once).
  const defs = await getTaskDefinitions();
  const progressResult = await query("SELECT taskDefId, claimed FROM UserTaskProgress WHERE userId = $1", [req.user.id]);
  const claimedSet = new Set(progressResult.rows.filter((p) => p.claimed).map((p) => p.taskdefid));
  claimedSet.add(def.id);
  const allDone = defs.every((d) => claimedSet.has(d.id));
  let bonusAwarded = false;
  if (allDone) {
    const already = await query("SELECT 1 FROM Transactions WHERE userId = $1 AND type = 'task_reward' AND meta->>'bonus' = 'true'", [req.user.id]);
    if (already.rows.length === 0) {
      const bonusResult = await query("SELECT value FROM AppSettings WHERE key = 'task_bonus_coins'");
      const bonusCoins = bonusResult.rows[0] ? Number(bonusResult.rows[0].value) : 20000;
      await query("UPDATE Wallets SET coinBalance = coinBalance + $1, updatedAt = now() WHERE userId = $2", [bonusCoins, req.user.id]);
      await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1,'task_reward',$2,$3)", [
        req.user.id, bonusCoins, JSON.stringify({ bonus: "true" }),
      ]);
      await query("INSERT INTO SystemMessages (userId, type, content) VALUES ($1,'task',$2)", [
        req.user.id, `You completed all 7 Days! Bonus: ${bonusCoins.toLocaleString()} coins has been added to your wallet`,
      ]);
      bonusAwarded = true;
    }
  }
  res.json({ message: "Claimed", rewardCoins: def.rewardcoins, grantedItem, bonusAwarded });
});

// Lets a user gift themselves (Day 6 Task 3), and also gives every gift a
// receiver-side "who sent it" / sender-side "who I sent it to" trail so the
// Day 7 "3 different people" tasks can be tracked accurately.
app.post("/api/gifts/self", requireAuth, async (req, res) => {
  const { giftId } = req.body;
  const giftResult = await query("SELECT * FROM Gifts WHERE id = $1", [giftId]);
  if (giftResult.rows.length === 0) return res.status(404).json({ error: "Gift not found" });
  const gift = giftResult.rows[0];
  const walletResult = await query("SELECT coinBalance FROM Wallets WHERE userId = $1", [req.user.id]);
  if (!walletResult.rows[0] || walletResult.rows[0].coinbalance < gift.coincost) return res.status(400).json({ error: "Insufficient coins" });
  await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1,'gift_sent',$2,$3)", [
    req.user.id, -gift.coincost, JSON.stringify({ giftName: gift.name, toSelf: "true", toUserId: req.user.id }),
  ]);
  await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1,'gift_received',$2,$3)", [
    req.user.id, gift.coincost, JSON.stringify({ giftName: gift.name, toSelf: "true", fromUserId: req.user.id }),
  ]);
  res.json({ message: `Gifted yourself ${gift.name}` });
});

// =================================================================
// STREAMS (Home v3 Live tab, Go Live, Follow tab's "Rooms You Manage")
// =================================================================
const streamKeyGen = customAlphabet("abcdefghijklmnopqrstuvwxyz0123456789", 10);

const STREAM_SELECT = `
  SELECT s.*, u.username AS hostUsername, u.avatar AS hostAvatar, u.createdAt AS hostCreatedAt,
         a.name AS agencyName,
         (SELECT COUNT(*)::int FROM RoomAdmins ra WHERE ra.streamId = s.id) + 1 AS hostCount,
         (SELECT claimed FROM UserTaskProgress utp JOIN TaskDefinitions td ON td.id = utp.taskDefId WHERE utp.userId = s.hostId AND td.trackingKey = 'bind_phone') AS day1Completed
  FROM LiveStreams s
  JOIN Users u ON u.id = s.hostId
  LEFT JOIN Agencies a ON a.id = u.agencyId
`;

function computeCategory(row) {
  if (row.roomtype === "video") return "Video";
  if (row.roomtype === "pk") return "PK";
  if (row.hostcount > 2) return "Party";
  const hostAgeDays = (Date.now() - new Date(row.hostcreatedat).getTime()) / (1000 * 60 * 60 * 24);
  if (hostAgeDays < 7 && row.day1completed !== true) return "New";
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
  const equipped = await getEquippedCosmetics(stream.hostid);
  const seatsResult = await query(
    `SELECT rs.seatNumber, rs.userId, u.username FROM RoomSeats rs LEFT JOIN Users u ON u.id = rs.userId WHERE rs.streamId = $1 ORDER BY rs.seatNumber`,
    [id]
  );
  res.json({
    stream: serializeStream(stream),
    roomCover: equipped.roomcover,
    seats: seatsResult.rows.map((s) => ({ seatNumber: s.seatnumber, userId: s.userid, username: s.username })),
    chatHistory: chatResult.rows.reverse().map((c) => ({ username: c.username, message: c.message, createdAt: c.createdat })),
  });
});

app.post("/api/streams/:id/seats/:num/take", requireAuth, async (req, res) => {
  const streamId = Number(req.params.id);
  const seatNumber = Number(req.params.num);
  if (seatNumber < 1 || seatNumber > 8) return res.status(400).json({ error: "seatNumber must be 1-8" });
  const taken = await query("SELECT userId FROM RoomSeats WHERE streamId = $1 AND seatNumber = $2", [streamId, seatNumber]);
  if (taken.rows[0]?.userid) return res.status(400).json({ error: "Seat already taken" });
  const already = await query("SELECT seatNumber FROM RoomSeats WHERE streamId = $1 AND userId = $2", [streamId, req.user.id]);
  if (already.rows.length > 0) await query("DELETE FROM RoomSeats WHERE streamId = $1 AND userId = $2", [streamId, req.user.id]);
  await query(
    `INSERT INTO RoomSeats (streamId, seatNumber, userId, occupiedAt) VALUES ($1,$2,$3,now())
     ON CONFLICT (streamId, seatNumber) DO UPDATE SET userId = $3, occupiedAt = now()`,
    [streamId, seatNumber, req.user.id]
  );
  res.json({ message: "Seat taken" });
});
app.post("/api/streams/:id/seats/leave", requireAuth, async (req, res) => {
  await query("DELETE FROM RoomSeats WHERE streamId = $1 AND userId = $2", [Number(req.params.id), req.user.id]);
  res.json({ message: "Left seat" });
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
    "SELECT id, amanaId, username, bio, gender, country, createdAt, agencyId, isHostBadge, isDbBadge, prettyId, verifiedType, dbCode FROM Users WHERE id = $1",
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
  let verifiedAgencyName = null;
  if (row.agencyid && (row.verifiedtype === "agency" || row.verifiedtype === "host")) {
    const agencyResult = await query("SELECT name FROM Agencies WHERE id = $1", [row.agencyid]);
    verifiedAgencyName = agencyResult.rows[0]?.name || null;
  }
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
    verifiedType: row.verifiedtype || "none",
    dbCode: row.dbcode,
    verifiedAgencyName,
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
    const giftResult = await query("SELECT id, name, coinCost, receiverSplitPct FROM Gifts WHERE id = $1", [giftId]);
    if (giftResult.rows.length === 0) return res.status(404).json({ error: "Gift not found" });
    const gift = giftResult.rows[0];
    if (!walletResult.rows[0] || walletResult.rows[0].coinbalance < gift.coincost) return res.status(400).json({ error: "Insufficient coins" });
    const hostShare = Math.round(gift.coincost * (gift.receiversplitpct / 100)); // same fixed commission used for gifts sent in a live room
    const [senderBefore, receiverBefore] = await Promise.all([getSendReceiveTotals(me), getSendReceiveTotals(receiverId)]);
    await query("UPDATE Wallets SET coinBalance = coinBalance - $1 WHERE userId = $2", [gift.coincost, me]);
    await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1,'gift_sent',$2,$3)", [
      me, -gift.coincost, JSON.stringify({ giftName: gift.name, via: "message", toUserId: receiverId }),
    ]);
    await query("UPDATE Wallets SET diamondBalance = diamondBalance + $1 WHERE userId = $2", [hostShare, receiverId]);
    await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1,'gift_received',$2,$3)", [
      receiverId, hostShare, JSON.stringify({ giftName: gift.name, via: "message", fromUserId: me }),
    ]);
    await Promise.all([
      notifyIfLeveledUp(me, "Send Level", "SendLevelTiers", senderBefore.sent, senderBefore.sent + gift.coincost, "task"),
      notifyIfLeveledUp(receiverId, "Receive Level", "ReceiveLevelTiers", receiverBefore.received, receiverBefore.received + hostShare, "task"),
    ]);
    await creditFamilyContribution(me, gift.coincost, "in a chat");
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
// DAILY TARGET SYSTEM - Agency + DB fixed-tier daily commission
// =================================================================
async function getAgencyTiers() {
  const r = await query("SELECT * FROM AgencyTargetTiers ORDER BY hostCountTier ASC");
  return r.rows.map((t) => ({ tier: t.hostcounttier, giftTarget: Number(t.gifttarget), reward: t.reward }));
}
async function getDbTiers() {
  const r = await query("SELECT * FROM DbTargetTiers ORDER BY agencyCountTier ASC");
  return r.rows.map((t) => ({ tier: t.agencycounttier, giftTarget: Number(t.gifttarget), reward: t.reward }));
}
// Highest tier where BOTH the count AND the gift total are met - no partial payment.
function highestTierReached(count, giftTotal, tiers) {
  let best = null;
  for (const t of tiers) if (count >= t.tier && giftTotal >= t.giftTarget) best = t;
  return best; // null = not reached
}
function todayDateStr() {
  return new Date().toISOString().slice(0, 10); // resets naturally at 12:00AM UTC
}
async function todaysGiftTotalForHosts(hostUserIds) {
  if (hostUserIds.length === 0) return 0;
  const r = await query(
    "SELECT COALESCE(SUM(amount),0) AS total FROM Transactions WHERE type = 'gift_received' AND userId = ANY($1) AND createdAt >= date_trunc('day', now())",
    [hostUserIds]
  );
  return Number(r.rows[0].total);
}

// Computes (without saving) every Agency/DB's status for today - used both
// for the Admin preview list and, at approval time, recomputed fresh so the
// payout always matches the latest numbers.
async function computeTodaysTargets() {
  const agencyTiers = await getAgencyTiers();
  const dbTiers = await getDbTiers();

  const agenciesResult = await query("SELECT id, name, ownerUserId FROM Agencies WHERE ownerUserId IS NOT NULL");
  const agencyRows = [];
  for (const agency of agenciesResult.rows) {
    const hostsResult = await query("SELECT id FROM Users WHERE agencyId = $1 AND verifiedType = 'host'", [agency.id]);
    const hostIds = hostsResult.rows.map((r) => r.id);
    const giftTotal = await todaysGiftTotalForHosts(hostIds);
    const tier = highestTierReached(hostIds.length, giftTotal, agencyTiers);
    agencyRows.push({
      agencyId: agency.id, agencyName: agency.name, ownerUserId: agency.ownerUserId,
      hostCount: hostIds.length, giftTotal, tier: tier ? tier.tier : 0, reward: tier ? tier.reward : 0,
    });
  }

  const dbsResult = await query("SELECT id, username, dbCode FROM Users WHERE verifiedType = 'db' AND dbCode IS NOT NULL");
  const dbRows = [];
  const dbHostRows = [];
  for (const db of dbsResult.rows) {
    const agenciesUnder = await query("SELECT id FROM Agencies WHERE dbId = $1", [db.dbcode]);
    const agencyIds = agenciesUnder.rows.map((r) => r.id);
    let hostIds = [];
    if (agencyIds.length > 0) {
      const hostsResult = await query("SELECT id FROM Users WHERE agencyId = ANY($1) AND verifiedType = 'host'", [agencyIds]);
      hostIds = hostsResult.rows.map((r) => r.id);
    }
    const giftTotal = await todaysGiftTotalForHosts(hostIds);
    const dbTier = highestTierReached(agencyIds.length, giftTotal, dbTiers);
    dbRows.push({
      dbUserId: db.id, dbCode: db.dbcode, username: db.username,
      agencyCount: agencyIds.length, giftTotal, tier: dbTier ? dbTier.tier : 0, reward: dbTier ? dbTier.reward : 0,
    });
    // Second, separate commission: same host network judged against the
    // Agency (host-count) tier table, per the "DB can earn 2 commissions" rule.
    const hostTier = highestTierReached(hostIds.length, giftTotal, agencyTiers);
    if (hostTier) {
      dbHostRows.push({
        dbUserId: db.id, dbCode: db.dbcode, username: db.username,
        hostCount: hostIds.length, giftTotal, tier: hostTier.tier, reward: hostTier.reward,
      });
    }
  }
  return { agencyRows, dbRows, dbHostRows };
}

app.get("/api/targets/agency/tiers", requireAuth, async (req, res) => {
  res.json({ tiers: await getAgencyTiers() });
});
app.get("/api/targets/db/tiers", requireAuth, async (req, res) => {
  res.json({ tiers: await getDbTiers() });
});
app.patch("/api/admin/targets/agency-tiers/:tier", requireAuth, requireAdmin, async (req, res) => {
  const { giftTarget, reward } = req.body;
  const fields = []; const params = []; let i = 1;
  if (giftTarget !== undefined) { fields.push(`giftTarget = $${i++}`); params.push(giftTarget); }
  if (reward !== undefined) { fields.push(`reward = $${i++}`); params.push(reward); }
  if (fields.length === 0) return res.status(400).json({ error: "Nothing to update" });
  params.push(Number(req.params.tier));
  await query(`UPDATE AgencyTargetTiers SET ${fields.join(", ")} WHERE hostCountTier = $${i}`, params);
  res.json({ message: "Tier updated" });
});
app.patch("/api/admin/targets/db-tiers/:tier", requireAuth, requireAdmin, async (req, res) => {
  const { giftTarget, reward } = req.body;
  const fields = []; const params = []; let i = 1;
  if (giftTarget !== undefined) { fields.push(`giftTarget = $${i++}`); params.push(giftTarget); }
  if (reward !== undefined) { fields.push(`reward = $${i++}`); params.push(reward); }
  if (fields.length === 0) return res.status(400).json({ error: "Nothing to update" });
  params.push(Number(req.params.tier));
  await query(`UPDATE DbTargetTiers SET ${fields.join(", ")} WHERE agencyCountTier = $${i}`, params);
  res.json({ message: "Tier updated" });
});

app.get("/api/admin/targets/today", requireAuth, requireAdmin, async (req, res) => {
  const { agencyRows, dbRows, dbHostRows } = await computeTodaysTargets();
  res.json({
    date: todayDateStr(),
    agenciesReached: agencyRows.filter((r) => r.tier > 0),
    dbReached: dbRows.filter((r) => r.tier > 0),
    dbHostReached: dbHostRows.filter((r) => r.tier > 0),
  });
});

app.post("/api/admin/targets/approve-all", requireAuth, requireAdmin, async (req, res) => {
  const date = todayDateStr();
  const { agencyRows, dbRows, dbHostRows } = await computeTodaysTargets();
  let paidCount = 0;

  for (const r of agencyRows) {
    if (r.tier === 0) continue;
    const already = await query("SELECT id FROM DailyTargetResults WHERE resultDate = $1 AND entityType = 'agency' AND entityId = $2 AND status = 'approved'", [date, r.agencyId]);
    if (already.rows.length > 0) continue;
    await query(
      `INSERT INTO DailyTargetResults (resultDate, entityType, entityId, countValue, giftTotal, tierReached, reward, status, approvedAt)
       VALUES ($1,'agency',$2,$3,$4,$5,$6,'approved',now())
       ON CONFLICT (resultDate, entityType, entityId) DO UPDATE SET countValue=$3, giftTotal=$4, tierReached=$5, reward=$6, status='approved', approvedAt=now()`,
      [date, r.agencyId, r.hostCount, r.giftTotal, r.tier, r.reward]
    );
    await query("UPDATE Wallets SET coinBalance = coinBalance + $1, updatedAt = now() WHERE userId = $2", [r.reward, r.ownerUserId]);
    await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1,'task_reward',$2,$3)", [
      r.ownerUserId, r.reward, JSON.stringify({ note: "Daily Agency Target", tier: r.tier, agencyId: r.agencyId }),
    ]);
    await query("INSERT INTO SystemMessages (userId, type, content) VALUES ($1,'task',$2)", [
      r.ownerUserId, `Congratulations! You reached Daily Target Tier ${r.tier}\nReward: ${r.reward.toLocaleString()} Coins has been added to your wallet`,
    ]);
    paidCount++;
  }
  for (const r of dbRows) {
    if (r.tier === 0) continue;
    const already = await query("SELECT id FROM DailyTargetResults WHERE resultDate = $1 AND entityType = 'db' AND entityId = $2 AND status = 'approved'", [date, r.dbUserId]);
    if (already.rows.length > 0) continue;
    await query(
      `INSERT INTO DailyTargetResults (resultDate, entityType, entityId, countValue, giftTotal, tierReached, reward, status, approvedAt)
       VALUES ($1,'db',$2,$3,$4,$5,$6,'approved',now())
       ON CONFLICT (resultDate, entityType, entityId) DO UPDATE SET countValue=$3, giftTotal=$4, tierReached=$5, reward=$6, status='approved', approvedAt=now()`,
      [date, r.dbUserId, r.agencyCount, r.giftTotal, r.tier, r.reward]
    );
    await query("UPDATE Wallets SET coinBalance = coinBalance + $1, updatedAt = now() WHERE userId = $2", [r.reward, r.dbUserId]);
    await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1,'task_reward',$2,$3)", [
      r.dbUserId, r.reward, JSON.stringify({ note: "Daily DB Target (Agency count)", tier: r.tier }),
    ]);
    await query("INSERT INTO SystemMessages (userId, type, content) VALUES ($1,'task',$2)", [
      r.dbUserId, `Congratulations! You reached Daily Target Tier ${r.tier}\nReward: ${r.reward.toLocaleString()} Coins has been added to your wallet`,
    ]);
    paidCount++;
  }
  for (const r of dbHostRows) {
    if (r.tier === 0) continue;
    const already = await query("SELECT id FROM DailyTargetResults WHERE resultDate = $1 AND entityType = 'db_host' AND entityId = $2 AND status = 'approved'", [date, r.dbUserId]);
    if (already.rows.length > 0) continue;
    await query(
      `INSERT INTO DailyTargetResults (resultDate, entityType, entityId, countValue, giftTotal, tierReached, reward, status, approvedAt)
       VALUES ($1,'db_host',$2,$3,$4,$5,$6,'approved',now())
       ON CONFLICT (resultDate, entityType, entityId) DO UPDATE SET countValue=$3, giftTotal=$4, tierReached=$5, reward=$6, status='approved', approvedAt=now()`,
      [date, r.dbUserId, r.hostCount, r.giftTotal, r.tier, r.reward]
    );
    await query("UPDATE Wallets SET coinBalance = coinBalance + $1, updatedAt = now() WHERE userId = $2", [r.reward, r.dbUserId]);
    await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1,'task_reward',$2,$3)", [
      r.dbUserId, r.reward, JSON.stringify({ note: "Daily DB Target (Host count - second commission)", tier: r.tier }),
    ]);
    await query("INSERT INTO SystemMessages (userId, type, content) VALUES ($1,'task',$2)", [
      r.dbUserId, `Congratulations! You reached Daily Target Tier ${r.tier} (Host network)\nReward: ${r.reward.toLocaleString()} Coins has been added to your wallet`,
    ]);
    paidCount++;
  }
  res.json({ message: `Approved and paid ${paidCount} target${paidCount === 1 ? "" : "s"}` });
});

// ---- Agency/DB's own "My Target" wallet view -----------------------------
app.get("/api/targets/my-status", requireAuth, async (req, res) => {
  const userResult = await query("SELECT verifiedType, dbCode, agencyId FROM Users WHERE id = $1", [req.user.id]);
  const u = userResult.rows[0];
  if (u.verifiedtype !== "agency" && u.verifiedtype !== "db") return res.status(400).json({ error: "Only verified Agency or DB accounts have a Daily Target" });
  const date = todayDateStr();
  const entityType = u.verifiedtype;
  let entityId = req.user.id;
  if (entityType === "agency") {
    const agencyResult = await query("SELECT id FROM Agencies WHERE ownerUserId = $1", [req.user.id]);
    entityId = agencyResult.rows[0]?.id;
  }
  const result = await query("SELECT * FROM DailyTargetResults WHERE resultDate = $1 AND entityType = $2 AND entityId = $3", [date, entityType, entityId]);
  const bonusResult = entityType === "db"
    ? await query("SELECT * FROM DailyTargetResults WHERE resultDate = $1 AND entityType = 'db_host' AND entityId = $2", [date, req.user.id])
    : { rows: [] };
  res.json({
    today: result.rows[0]
      ? { tierReached: result.rows[0].tierreached, reward: result.rows[0].reward, status: result.rows[0].status }
      : { tierReached: 0, reward: 0, status: "not_reached" },
    hostBonus: bonusResult.rows[0]
      ? { tierReached: bonusResult.rows[0].tierreached, reward: bonusResult.rows[0].reward, status: bonusResult.rows[0].status }
      : null,
  });
});

// =================================================================
// STORE + DRESS UP - Frames / Rides / Room Covers (30-day, stackable)
// =================================================================
async function getAppSetting(key) {
  const r = await query("SELECT value FROM AppSettings WHERE key = $1", [key]);
  return r.rows[0] ? r.rows[0].value : null;
}
async function setAppSetting(key, value) {
  await query("INSERT INTO AppSettings (key, value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value = $2", [key, JSON.stringify(value)]);
}
function storeItemPrice(item) {
  const onSale = item.saleendsat && new Date(item.saleendsat) > new Date() && item.salediscountpct > 0;
  const price = onSale ? Math.round(item.price * (1 - item.salediscountpct / 100)) : item.price;
  return { price, onSale, originalPrice: item.price, saleDiscountPct: onSale ? item.salediscountpct : 0 };
}
function mapStoreItem(item) {
  const pricing = storeItemPrice(item);
  return {
    id: item.id, category: item.category, name: item.name, effect: item.effect,
    durationDays: item.durationdays, active: item.active, ...pricing,
  };
}

app.get("/api/store/items", requireAuth, async (req, res) => {
  const enabled = await getAppSetting("store_enabled");
  if (enabled === false) return res.json({ enabled: false, items: [] });
  const category = req.query.category; // frame | ride | roomcover | undefined(all)
  const result = category
    ? await query("SELECT * FROM StoreItems WHERE category = $1 AND active = TRUE ORDER BY price ASC", [category])
    : await query("SELECT * FROM StoreItems WHERE active = TRUE ORDER BY category, price ASC");
  res.json({ enabled: true, items: result.rows.map(mapStoreItem) });
});

app.post("/api/store/buy", requireAuth, async (req, res) => {
  const enabled = await getAppSetting("store_enabled");
  if (enabled === false) return res.status(400).json({ error: "The Store is currently unavailable" });
  const { itemId } = req.body;
  const itemResult = await query("SELECT * FROM StoreItems WHERE id = $1 AND active = TRUE", [itemId]);
  if (itemResult.rows.length === 0) return res.status(404).json({ error: "Item not found" });
  const item = itemResult.rows[0];
  const pricing = storeItemPrice(item);
  const walletResult = await query("SELECT coinBalance FROM Wallets WHERE userId = $1", [req.user.id]);
  if (!walletResult.rows[0] || walletResult.rows[0].coinbalance < pricing.price) return res.status(400).json({ error: "Insufficient coin balance" });

  const existing = await query("SELECT * FROM UserInventory WHERE userId = $1 AND itemId = $2", [req.user.id, itemId]);
  const isNew = existing.rows.length === 0;
  const durationMs = item.durationdays * 24 * 60 * 60 * 1000;

  await query("UPDATE Wallets SET coinBalance = coinBalance - $1, updatedAt = now() WHERE userId = $2", [pricing.price, req.user.id]);
  await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1,'purchase',$2,$3)", [
    req.user.id, -pricing.price, JSON.stringify({ note: `Store: ${item.name}`, itemId }),
  ]);

  if (isNew) {
    await query("INSERT INTO UserInventory (userId, itemId, expiresAt) VALUES ($1,$2, now() + $3::interval)", [
      req.user.id, itemId, `${item.durationdays} days`,
    ]);
    // Broadcast only on a brand-new purchase, not on a stack/renew.
    await query("INSERT INTO SystemMessages (userId, type, content) VALUES ($1,'recharge',$2)", [
      req.user.id, `You purchased ${item.name}! It's ready in Dress Up.`,
    ]);
  } else {
    const current = existing.rows[0];
    // Stack from the later of "now" or the current expiry, so it's always +N days from whichever is later.
    const base = new Date(current.expiresat) > new Date() ? current.expiresat : new Date();
    await query("UPDATE UserInventory SET expiresAt = $1::timestamptz + $2::interval, notifiedExpirySoon = FALSE WHERE id = $3", [
      base, `${item.durationdays} days`, current.id,
    ]);
  }
  res.json({ message: `${item.name} ${isNew ? "purchased" : "extended"} - +${item.durationdays} days`, isNew });
});

app.post("/api/store/renew/:inventoryId", requireAuth, async (req, res) => {
  const invResult = await query(
    "SELECT ui.id AS invid, ui.expiresAt, si.price, si.durationDays, si.name, si.saleDiscountPct, si.saleEndsAt FROM UserInventory ui JOIN StoreItems si ON si.id = ui.itemId WHERE ui.id = $1 AND ui.userId = $2",
    [Number(req.params.inventoryId), req.user.id]
  );
  if (invResult.rows.length === 0) return res.status(404).json({ error: "Item not found in your inventory" });
  const row = invResult.rows[0];
  const pricing = storeItemPrice({ price: row.price, salediscountpct: row.salediscountpct, saleendsat: row.saleendsat });
  const walletResult = await query("SELECT coinBalance FROM Wallets WHERE userId = $1", [req.user.id]);
  if (!walletResult.rows[0] || walletResult.rows[0].coinbalance < pricing.price) return res.status(400).json({ error: "Insufficient coin balance" });
  await query("UPDATE Wallets SET coinBalance = coinBalance - $1, updatedAt = now() WHERE userId = $2", [pricing.price, req.user.id]);
  await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1,'purchase',$2,$3)", [
    req.user.id, -pricing.price, JSON.stringify({ note: `Store renew: ${row.name}` }),
  ]);
  const base = new Date(row.expiresat) > new Date() ? row.expiresat : new Date();
  await query("UPDATE UserInventory SET expiresAt = $1::timestamptz + $2::interval, notifiedExpirySoon = FALSE WHERE id = $3", [
    base, `${row.durationdays} days`, row.invid,
  ]);
  res.json({ message: `${row.name} renewed - +${row.durationdays} days` });
});

// ---- Dress Up (equip/unequip inventory) ----
app.get("/api/dressup/inventory", requireAuth, async (req, res) => {
  const enabled = await getAppSetting("dressup_enabled");
  if (enabled === false) return res.json({ enabled: false });
  const result = await query(
    `SELECT ui.*, si.name, si.category, si.effect FROM UserInventory ui JOIN StoreItems si ON si.id = ui.itemId WHERE ui.userId = $1 ORDER BY ui.expiresAt DESC`,
    [req.user.id]
  );
  const now = Date.now();
  const active = [];
  const expired = [];
  for (const r of result.rows) {
    const msLeft = new Date(r.expiresat).getTime() - now;
    const row = {
      id: r.id, itemId: r.itemid, name: r.name, category: r.category, effect: r.effect,
      equipped: r.equipped, expiresAt: r.expiresat, daysLeft: Math.max(0, Math.ceil(msLeft / 86400000)),
      hoursLeft: Math.max(0, Math.floor((msLeft % 86400000) / 3600000)),
    };
    if (msLeft > 0) active.push(row);
    else expired.push(row);
  }
  res.json({ enabled: true, active, expired });
});
app.post("/api/dressup/equip/:inventoryId", requireAuth, async (req, res) => {
  const invResult = await query("SELECT ui.*, si.category FROM UserInventory ui JOIN StoreItems si ON si.id = ui.itemId WHERE ui.id = $1 AND ui.userId = $2", [
    Number(req.params.inventoryId), req.user.id,
  ]);
  if (invResult.rows.length === 0) return res.status(404).json({ error: "Item not found" });
  const row = invResult.rows[0];
  if (new Date(row.expiresat) < new Date()) return res.status(400).json({ error: "This item has expired - renew it first" });
  await query(
    "UPDATE UserInventory SET equipped = FALSE WHERE userId = $1 AND itemId IN (SELECT id FROM StoreItems WHERE category = $2)",
    [req.user.id, row.category]
  );
  await query("UPDATE UserInventory SET equipped = TRUE WHERE id = $1", [row.id]);
  res.json({ message: "Equipped" });
});
app.post("/api/dressup/unequip/:inventoryId", requireAuth, async (req, res) => {
  await query("UPDATE UserInventory SET equipped = FALSE WHERE id = $1 AND userId = $2", [Number(req.params.inventoryId), req.user.id]);
  res.json({ message: "Unequipped" });
});
// Called opportunistically (e.g. when Dress Up loads) since there's no
// background job scheduler in this setup - it's not a true push notification,
// but it reaches the "3 days left" warning without needing a cron worker.
app.post("/api/dressup/check-expiring", requireAuth, async (req, res) => {
  const result = await query(
    `SELECT ui.id, si.name FROM UserInventory ui JOIN StoreItems si ON si.id = ui.itemId
     WHERE ui.userId = $1 AND ui.notifiedExpirySoon = FALSE
       AND ui.expiresAt > now() AND ui.expiresAt < now() + interval '3 days'`,
    [req.user.id]
  );
  for (const row of result.rows) {
    await query("INSERT INTO SystemMessages (userId, type, content) VALUES ($1,'task',$2)", [
      req.user.id, `Your ${row.name} will expire soon.`,
    ]);
    await query("UPDATE UserInventory SET notifiedExpirySoon = TRUE WHERE id = $1", [row.id]);
  }
  res.json({ notified: result.rows.length });
});
// Returns the currently-equipped Frame/Ride/Room Cover for any user (used
// to render cosmetics on Profile, Moments, etc. once those are wired up).
async function getEquippedCosmetics(userId) {
  const result = await query(
    `SELECT si.category, si.name, si.effect FROM UserInventory ui JOIN StoreItems si ON si.id = ui.itemId
     WHERE ui.userId = $1 AND ui.equipped = TRUE AND ui.expiresAt > now()`,
    [userId]
  );
  const out = { frame: null, ride: null, roomcover: null };
  for (const r of result.rows) out[r.category] = { name: r.name, effect: r.effect };
  return out;
}
app.get("/api/dressup/equipped/:userId", requireAuth, async (req, res) => {
  res.json(await getEquippedCosmetics(Number(req.params.userId)));
});

// =================================================================
// VERIFY CENTER - DB / Agency / Host supervision hierarchy
// =================================================================
async function generateDbCode() {
  const r = await query("SELECT COUNT(*) FROM Users WHERE dbCode IS NOT NULL");
  return "DB" + String(Number(r.rows[0].count) + 1).padStart(3, "0");
}
async function generateAgencyCode() {
  const r = await query("SELECT COUNT(*) FROM Agencies WHERE agencyCode IS NOT NULL");
  return "AG" + String(Number(r.rows[0].count) + 1).padStart(3, "0");
}
// Badge shown on Profile / Moments / anywhere a user is displayed.
function verificationBadge(user) {
  if (user.verifiedtype === "db") return { type: "db", label: "DB", code: user.dbcode };
  if (user.verifiedtype === "agency") return { type: "agency", label: "AGENCY", code: null };
  if (user.verifiedtype === "host") return { type: "host", label: "HOST", code: null };
  return null;
}

app.get("/api/verify/status", requireAuth, async (req, res) => {
  const userResult = await query(
    "SELECT verifiedType, dbCode, supervisingDbId, verificationRejectionReason, agencyId FROM Users WHERE id = $1",
    [req.user.id]
  );
  const u = userResult.rows[0];
  const pendingResult = await query(
    "SELECT id, type, createdAt FROM VerificationRequests WHERE userId = $1 AND status = 'pending' ORDER BY createdAt DESC LIMIT 1",
    [req.user.id]
  );
  let agencyName = null;
  if (u.agencyid) {
    const agencyResult = await query("SELECT name, agencyCode FROM Agencies WHERE id = $1", [u.agencyid]);
    if (agencyResult.rows[0]) agencyName = agencyResult.rows[0].name;
  }
  res.json({
    verifiedType: u.verifiedtype || "none",
    dbCode: u.dbcode,
    supervisingDbId: u.supervisingdbid,
    agencyName,
    rejectionReason: u.verificationrejectionreason,
    pending: pendingResult.rows[0] ? { id: pendingResult.rows[0].id, type: pendingResult.rows[0].type, createdAt: pendingResult.rows[0].createdat } : null,
  });
});

app.get("/api/verify/lookup/db/:code", requireAuth, async (req, res) => {
  const result = await query("SELECT username FROM Users WHERE dbCode = $1", [req.params.code.trim()]);
  res.json({ exists: result.rows.length > 0, name: result.rows[0]?.username || null });
});
app.get("/api/verify/lookup/agency/:code", requireAuth, async (req, res) => {
  const result = await query("SELECT name FROM Agencies WHERE agencyCode = $1", [req.params.code.trim()]);
  res.json({ exists: result.rows.length > 0, name: result.rows[0]?.name || null });
});

async function assertCanApply(userId) {
  const userResult = await query("SELECT verifiedType FROM Users WHERE id = $1", [userId]);
  if (userResult.rows[0].verifiedtype && userResult.rows[0].verifiedtype !== "none") {
    throw new Error("You're already verified. Unverify first to apply for a different type.");
  }
  const pending = await query("SELECT id FROM VerificationRequests WHERE userId = $1 AND status = 'pending'", [userId]);
  if (pending.rows.length > 0) throw new Error("You already have a pending verification request.");
}

app.post("/api/verify/apply/db", requireAuth, async (req, res) => {
  try {
    await assertCanApply(req.user.id);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
  const { fullName, phone, country, idCardNumber, idCardFrontUrl, idCardBackUrl, selfieUrl } = req.body;
  if (!fullName || !phone || !country || !idCardNumber || !idCardFrontUrl || !idCardBackUrl || !selfieUrl) {
    return res.status(400).json({ error: "All fields are required" });
  }
  await query("INSERT INTO VerificationRequests (userId, type, fields) VALUES ($1,'db',$2)", [
    req.user.id, JSON.stringify({ fullName, phone, country, idCardNumber, idCardFrontUrl, idCardBackUrl, selfieUrl }),
  ]);
  res.json({ message: "DB request submitted - processing takes 24-48 hours" });
});

app.post("/api/verify/apply/agency", requireAuth, async (req, res) => {
  try {
    await assertCanApply(req.user.id);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
  const { supervisingDbId, agencyName, fullName, phone, country, monthlyUserGoal, logoUrl, description, email } = req.body;
  if (!supervisingDbId || !agencyName || !fullName || !phone || !country || !monthlyUserGoal || !logoUrl || !email) {
    return res.status(400).json({ error: "All required fields must be filled" });
  }
  const dbCheck = await query("SELECT id FROM Users WHERE dbCode = $1", [supervisingDbId.trim()]);
  if (dbCheck.rows.length === 0) return res.status(400).json({ error: "That DB ID doesn't exist" });
  const nameClash = await query("SELECT id FROM Agencies WHERE name = $1", [agencyName.trim()]);
  if (nameClash.rows.length > 0) return res.status(409).json({ error: "That agency name is taken" });
  await query("INSERT INTO VerificationRequests (userId, type, fields) VALUES ($1,'agency',$2)", [
    req.user.id,
    JSON.stringify({ supervisingDbId: supervisingDbId.trim(), agencyName, fullName, phone, country, monthlyUserGoal, logoUrl, description, email }),
  ]);
  res.json({ message: "Agency request submitted - processing takes 24-48 hours" });
});

app.post("/api/verify/apply/host", requireAuth, async (req, res) => {
  try {
    await assertCanApply(req.user.id);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
  const { agencyCode, fullName, phone, gender, photoUrl } = req.body;
  if (!agencyCode || !fullName || !phone || !gender || !photoUrl) return res.status(400).json({ error: "All fields are required" });
  const agencyCheck = await query("SELECT id, name FROM Agencies WHERE agencyCode = $1", [agencyCode.trim()]);
  if (agencyCheck.rows.length === 0) return res.status(400).json({ error: "That Agency ID doesn't exist" });
  await query("INSERT INTO VerificationRequests (userId, type, fields) VALUES ($1,'host',$2)", [
    req.user.id, JSON.stringify({ agencyCode: agencyCode.trim(), fullName, phone, gender, photoUrl }),
  ]);
  res.json({ message: "Host request submitted to the Agency for approval" });
});

app.post("/api/verify/unverify", requireAuth, async (req, res) => {
  await query(
    "UPDATE Users SET verifiedType = 'none', supervisingDbId = NULL, isHostBadge = FALSE, isDbBadge = FALSE, agencyId = NULL WHERE id = $1",
    [req.user.id]
  );
  res.json({ message: "You are now unverified. You can apply again." });
});

// ---- Approval (Admin, or the specific supervising DB / Agency) -----------
async function canReviewRequest(reviewer, request) {
  if (isAdminEmail(reviewer.email)) return true;
  if (request.type === "agency") {
    const dbResult = await query("SELECT dbCode FROM Users WHERE id = $1", [reviewer.id]);
    return dbResult.rows[0]?.dbcode && dbResult.rows[0].dbcode === request.fields.supervisingDbId;
  }
  if (request.type === "host") {
    const agencyResult = await query("SELECT agencyCode FROM Agencies WHERE ownerUserId = $1", [reviewer.id]);
    return agencyResult.rows[0]?.agencycode && agencyResult.rows[0].agencycode === request.fields.agencyCode;
  }
  return false; // DB requests: Admin only
}
async function approveVerification(request) {
  const userId = request.userid;
  if (request.type === "db") {
    const code = await generateDbCode();
    await query("UPDATE Users SET verifiedType = 'db', dbCode = $1, isDbBadge = TRUE WHERE id = $2", [code, userId]);
  } else if (request.type === "agency") {
    const code = await generateAgencyCode();
    const f = request.fields;
    const agencyResult = await query(
      `INSERT INTO Agencies (name, ownerUserId, agencyCode, dbId, description, logoUrl, monthlyUserGoal, fullName, phone, country, email)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id`,
      [f.agencyName, userId, code, f.supervisingDbId, f.description || null, f.logoUrl, f.monthlyUserGoal, f.fullName, f.phone, f.country, f.email]
    );
    await query("UPDATE Users SET verifiedType = 'agency', agencyId = $1, supervisingDbId = $2 WHERE id = $3", [
      agencyResult.rows[0].id, f.supervisingDbId, userId,
    ]);
  } else if (request.type === "host") {
    const f = request.fields;
    const agencyResult = await query("SELECT id, dbId FROM Agencies WHERE agencyCode = $1", [f.agencyCode]);
    const agency = agencyResult.rows[0];
    await query("UPDATE Users SET verifiedType = 'host', agencyId = $1, supervisingDbId = $2, isHostBadge = TRUE WHERE id = $3", [
      agency.id, agency.dbid, userId,
    ]);
  }
  await query("INSERT INTO SystemMessages (userId, type, content) VALUES ($1,'task',$2)", [
    userId, `Your ${request.type.toUpperCase()} verification was approved!`,
  ]);
}
app.post("/api/verify/requests/:id/approve", requireAuth, async (req, res) => {
  const result = await query("SELECT * FROM VerificationRequests WHERE id = $1 AND status = 'pending'", [Number(req.params.id)]);
  if (result.rows.length === 0) return res.status(404).json({ error: "Request not found or already resolved" });
  const request = result.rows[0];
  if (!(await canReviewRequest(req.user, request))) return res.status(403).json({ error: "You're not authorized to approve this request" });
  await approveVerification(request);
  await query("UPDATE VerificationRequests SET status = 'approved', resolvedBy = $1, resolvedAt = now() WHERE id = $2", [req.user.id, request.id]);
  res.json({ message: "Approved" });
});
app.post("/api/verify/requests/:id/reject", requireAuth, async (req, res) => {
  const { reason } = req.body;
  const result = await query("SELECT * FROM VerificationRequests WHERE id = $1 AND status = 'pending'", [Number(req.params.id)]);
  if (result.rows.length === 0) return res.status(404).json({ error: "Request not found or already resolved" });
  const request = result.rows[0];
  if (!(await canReviewRequest(req.user, request))) return res.status(403).json({ error: "You're not authorized to reject this request" });
  await query("UPDATE VerificationRequests SET status = 'rejected', rejectionReason = $1, resolvedBy = $2, resolvedAt = now() WHERE id = $3", [
    reason || "Not specified", req.user.id, request.id,
  ]);
  await query("UPDATE Users SET verificationRejectionReason = $1 WHERE id = $2", [reason || "Not specified", request.userid]);
  await query("INSERT INTO SystemMessages (userId, type, content) VALUES ($1,'task',$2)", [
    request.userid, `Your ${request.type.toUpperCase()} verification was rejected: ${reason || "Not specified"}. You can reapply immediately.`,
  ]);
  res.json({ message: "Rejected" });
});

app.get("/api/verify/requests", requireAuth, requireAdmin, async (req, res) => {
  const type = req.query.type; // db | agency | host | undefined(all)
  const status = req.query.status || "pending";
  let where = "vr.status = $1";
  const params = [status];
  if (type && type !== "all") { where += " AND vr.type = $2"; params.push(type); }
  const result = await query(
    `SELECT vr.*, u.username, u.amanaId FROM VerificationRequests vr JOIN Users u ON u.id = vr.userId WHERE ${where} ORDER BY vr.createdAt ASC`,
    params
  );
  res.json({
    requests: result.rows.map((r) => ({
      id: r.id, type: r.type, fields: r.fields, status: r.status, username: r.username, amanaId: r.amanaid, createdAt: r.createdat,
    })),
  });
});
// Same list, but scoped to what the current DB / Agency owner is allowed to see.
app.get("/api/verify/my-requests", requireAuth, async (req, res) => {
  const userResult = await query("SELECT dbCode FROM Users WHERE id = $1", [req.user.id]);
  const agencyResult = await query("SELECT agencyCode FROM Agencies WHERE ownerUserId = $1", [req.user.id]);
  const dbCode = userResult.rows[0].dbcode;
  const agencyCode = agencyResult.rows[0]?.agencycode;
  const requests = [];
  if (dbCode) {
    const r = await query("SELECT vr.*, u.username FROM VerificationRequests vr JOIN Users u ON u.id = vr.userId WHERE vr.type = 'agency' AND vr.status = 'pending' AND vr.fields->>'supervisingDbId' = $1 ORDER BY vr.createdAt ASC", [dbCode]);
    requests.push(...r.rows);
  }
  if (agencyCode) {
    const r = await query("SELECT vr.*, u.username FROM VerificationRequests vr JOIN Users u ON u.id = vr.userId WHERE vr.type = 'host' AND vr.status = 'pending' AND vr.fields->>'agencyCode' = $1 ORDER BY vr.createdAt ASC", [agencyCode]);
    requests.push(...r.rows);
  }
  res.json({ requests: requests.map((r) => ({ id: r.id, type: r.type, fields: r.fields, status: r.status, username: r.username, createdAt: r.createdat })) });
});

app.get("/api/verify/db-team", requireAuth, async (req, res) => {
  const userResult = await query("SELECT dbCode FROM Users WHERE id = $1", [req.user.id]);
  const dbCode = userResult.rows[0].dbcode;
  if (!dbCode) return res.status(400).json({ error: "You're not a verified DB" });
  const [agencies, hosts] = await Promise.all([
    query("SELECT id, name, agencyCode FROM Agencies WHERE dbId = $1", [dbCode]),
    query("SELECT id, username, prettyId FROM Users WHERE supervisingDbId = $1 AND verifiedType = 'host'", [dbCode]),
  ]);
  res.json({
    team: [
      ...agencies.rows.map((a) => ({ type: "agency", name: a.name, code: a.agencycode })),
      ...hosts.rows.map((h) => ({ type: "host", name: h.username, code: h.prettyid || null })),
    ],
  });
});

// =================================================================
// ADMIN PANEL
// =================================================================
app.get("/api/admin/dashboard", requireAuth, requireAdmin, async (req, res) => {
  const [users, coinsInCirculation, diamondsInCirculation, pendingReseller, families, activeStreams] = await Promise.all([
    query("SELECT COUNT(*) FROM Users"),
    query("SELECT COALESCE(SUM(coinBalance),0) AS total FROM Wallets"),
    query("SELECT COALESCE(SUM(diamondBalance),0) AS total FROM Wallets"),
    query("SELECT COUNT(*) FROM ResellerDeals WHERE status = 'pending'"),
    query("SELECT COUNT(*) FROM Families"),
    query("SELECT COUNT(*) FROM LiveStreams WHERE endedAt IS NULL"),
  ]);
  res.json({
    totalUsers: Number(users.rows[0].count),
    coinsInCirculation: Number(coinsInCirculation.rows[0].total),
    diamondsInCirculation: Number(diamondsInCirculation.rows[0].total),
    pendingResellerDeals: Number(pendingReseller.rows[0].count),
    totalFamilies: Number(families.rows[0].count),
    activeStreams: Number(activeStreams.rows[0].count),
  });
});

// ---- Gifts CRUD -----------------------------------------------------------
app.post("/api/admin/gifts", requireAuth, requireAdmin, async (req, res) => {
  const { name, icon, coinCost, minVipLevel } = req.body;
  if (!name || !icon || !Number.isInteger(coinCost)) return res.status(400).json({ error: "name, icon, and coinCost are required" });
  const result = await query("INSERT INTO Gifts (name, icon, coinCost, minVipLevel) VALUES ($1,$2,$3,$4) RETURNING id", [
    name, icon, coinCost, minVipLevel || 0,
  ]);
  res.json({ message: "Gift created", id: result.rows[0].id });
});
app.patch("/api/admin/gifts/:id", requireAuth, requireAdmin, async (req, res) => {
  const { name, icon, coinCost, minVipLevel } = req.body;
  const fields = []; const params = []; let i = 1;
  if (name !== undefined) { fields.push(`name = $${i++}`); params.push(name); }
  if (icon !== undefined) { fields.push(`icon = $${i++}`); params.push(icon); }
  if (coinCost !== undefined) { fields.push(`coinCost = $${i++}`); params.push(coinCost); }
  if (minVipLevel !== undefined) { fields.push(`minVipLevel = $${i++}`); params.push(minVipLevel); }
  if (fields.length === 0) return res.status(400).json({ error: "Nothing to update" });
  params.push(Number(req.params.id));
  await query(`UPDATE Gifts SET ${fields.join(", ")} WHERE id = $${i}`, params);
  res.json({ message: "Gift updated" });
});
app.delete("/api/admin/gifts/:id", requireAuth, requireAdmin, async (req, res) => {
  await query("DELETE FROM Gifts WHERE id = $1", [Number(req.params.id)]);
  res.json({ message: "Gift deleted" });
});

// ---- Official Messages CRUD ------------------------------------------------
app.post("/api/admin/official-messages", requireAuth, requireAdmin, async (req, res) => {
  const { title, content } = req.body;
  if (!title || !content) return res.status(400).json({ error: "title and content are required" });
  const result = await query("INSERT INTO OfficialMessages (title, content) VALUES ($1,$2) RETURNING id", [title, content]);
  res.json({ message: "Broadcast sent", id: result.rows[0].id });
});
app.delete("/api/admin/official-messages/:id", requireAuth, requireAdmin, async (req, res) => {
  await query("DELETE FROM OfficialMessages WHERE id = $1", [Number(req.params.id)]);
  res.json({ message: "Deleted" });
});

// ---- Agencies CRUD ----------------------------------------------------------
app.post("/api/admin/agencies", requireAuth, requireAdmin, async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: "name is required" });
  const result = await query("INSERT INTO Agencies (name) VALUES ($1) RETURNING id", [name]);
  res.json({ message: "Agency created", id: result.rows[0].id });
});
app.get("/api/admin/agencies", requireAuth, requireAdmin, async (req, res) => {
  const result = await query(
    `SELECT a.id, a.name, (SELECT COUNT(*) FROM Users u WHERE u.agencyId = a.id) AS memberCount FROM Agencies a ORDER BY a.name ASC`
  );
  res.json({ agencies: result.rows.map((r) => ({ id: r.id, name: r.name, memberCount: Number(r.membercount) })) });
});
app.delete("/api/admin/agencies/:id", requireAuth, requireAdmin, async (req, res) => {
  await query("UPDATE Users SET agencyId = NULL WHERE agencyId = $1", [Number(req.params.id)]);
  await query("DELETE FROM Agencies WHERE id = $1", [Number(req.params.id)]);
  res.json({ message: "Agency deleted" });
});
app.get("/api/admin/agencies/applications", requireAuth, requireAdmin, async (req, res) => {
  const result = await query(
    "SELECT id, username, prettyId, agencyApplicationDbId FROM Users WHERE agencyApplicationStatus = 'pending'"
  );
  res.json({ applications: result.rows.map((r) => ({ userId: r.id, username: r.username, prettyId: r.prettyid, dbId: r.agencyapplicationdbid })) });
});
app.post("/api/admin/agencies/applications/:userId/respond", requireAuth, requireAdmin, async (req, res) => {
  const { agencyId, approve } = req.body;
  if (approve) {
    await query("UPDATE Users SET agencyId = $1, agencyApplicationStatus = 'none' WHERE id = $2", [agencyId, Number(req.params.userId)]);
  } else {
    await query("UPDATE Users SET agencyApplicationStatus = 'none' WHERE id = $1", [Number(req.params.userId)]);
  }
  res.json({ message: approve ? "Application approved" : "Application rejected" });
});

// ---- User search + badge toggles (Host / DB) --------------------------------
app.get("/api/admin/users/search", requireAuth, requireAdmin, async (req, res) => {
  const q = (req.query.q || "").trim();
  const result = await query(
    "SELECT id, username, amanaId, prettyId, isHostBadge, isDbBadge, agencyId FROM Users WHERE username ILIKE $1 OR amanaId ILIKE $1 LIMIT 20",
    [`%${q}%`]
  );
  res.json({
    users: result.rows.map((r) => ({
      id: r.id, username: r.username, amanaId: r.amanaid, prettyId: r.prettyid,
      isHostBadge: r.ishostbadge, isDbBadge: r.isdbbadge, agencyId: r.agencyid,
    })),
  });
});
app.post("/api/admin/users/:id/badges", requireAuth, requireAdmin, async (req, res) => {
  const { isHostBadge, isDbBadge } = req.body;
  const fields = []; const params = []; let i = 1;
  if (isHostBadge !== undefined) { fields.push(`isHostBadge = $${i++}`); params.push(isHostBadge); }
  if (isDbBadge !== undefined) { fields.push(`isDbBadge = $${i++}`); params.push(isDbBadge); }
  if (fields.length === 0) return res.status(400).json({ error: "Nothing to update" });
  params.push(Number(req.params.id));
  await query(`UPDATE Users SET ${fields.join(", ")} WHERE id = $${i}`, params);
  res.json({ message: "Badges updated" });
});

// ---- Store / Dress Up admin -------------------------------------------------
app.get("/api/admin/store/items", requireAuth, requireAdmin, async (req, res) => {
  const result = await query("SELECT * FROM StoreItems ORDER BY category, price ASC");
  res.json({ items: result.rows.map(mapStoreItem) });
});
app.patch("/api/admin/store/items/:id", requireAuth, requireAdmin, async (req, res) => {
  const { price, durationDays, active } = req.body;
  const fields = []; const params = []; let i = 1;
  if (price !== undefined) { fields.push(`price = $${i++}`); params.push(price); }
  if (durationDays !== undefined) { fields.push(`durationDays = $${i++}`); params.push(durationDays); }
  if (active !== undefined) { fields.push(`active = $${i++}`); params.push(active); }
  if (fields.length === 0) return res.status(400).json({ error: "Nothing to update" });
  params.push(Number(req.params.id));
  await query(`UPDATE StoreItems SET ${fields.join(", ")} WHERE id = $${i}`, params);
  res.json({ message: "Item updated" });
});
app.post("/api/admin/store/items/:id/sale", requireAuth, requireAdmin, async (req, res) => {
  const { discountPct, days } = req.body;
  if (!Number.isInteger(discountPct) || discountPct <= 0 || discountPct > 90) return res.status(400).json({ error: "discountPct must be between 1 and 90" });
  await query("UPDATE StoreItems SET saleDiscountPct = $1, saleEndsAt = now() + $2::interval WHERE id = $3", [
    discountPct, `${days || 30} days`, Number(req.params.id),
  ]);
  res.json({ message: `${discountPct}% sale started for ${days || 30} days` });
});
app.post("/api/admin/store/toggle", requireAuth, requireAdmin, async (req, res) => {
  const { store, dressUp } = req.body;
  if (store !== undefined) await setAppSetting("store_enabled", store);
  if (dressUp !== undefined) await setAppSetting("dressup_enabled", dressUp);
  res.json({ message: "Settings updated" });
});
app.get("/api/admin/store/settings", requireAuth, requireAdmin, async (req, res) => {
  res.json({
    storeEnabled: (await getAppSetting("store_enabled")) !== false,
    dressUpEnabled: (await getAppSetting("dressup_enabled")) !== false,
  });
});
app.get("/api/admin/store/purchases", requireAuth, requireAdmin, async (req, res) => {
  const result = await query(
    `SELECT ui.id, u.username, si.name, si.category, ui.purchasedAt, ui.expiresAt, ui.equipped
     FROM UserInventory ui JOIN Users u ON u.id = ui.userId JOIN StoreItems si ON si.id = ui.itemId
     ORDER BY ui.purchasedAt DESC LIMIT 200`
  );
  res.json({
    purchases: result.rows.map((r) => ({
      id: r.id, username: r.username, itemName: r.name, category: r.category,
      purchasedAt: r.purchasedat, expiresAt: r.expiresat, equipped: r.equipped,
      expired: new Date(r.expiresat) < new Date(),
    })),
  });
});

// ---- 7-Day Task admin -------------------------------------------------------
app.get("/api/admin/tasks", requireAuth, requireAdmin, async (req, res) => {
  const result = await query("SELECT * FROM TaskDefinitions ORDER BY day ASC, orderInDay ASC");
  const settingsResult = await query("SELECT key, value FROM AppSettings WHERE key IN ('newuser_task_enabled','task_bonus_coins')");
  const settings = {};
  settingsResult.rows.forEach((r) => { settings[r.key] = r.value; });
  res.json({
    enabled: settings.newuser_task_enabled !== false,
    bonusCoins: settings.task_bonus_coins !== undefined ? Number(settings.task_bonus_coins) : 20000,
    tasks: result.rows.map((t) => ({
      id: t.id, day: t.day, order: t.orderinday, title: t.title, trackingKey: t.trackingkey,
      target: t.targetvalue, rewardCoins: t.rewardcoins, rewardItemCategory: t.rewarditemcategory,
      rewardItemName: t.rewarditemname, rewardItemDays: t.rewarditemdays, manual: t.manual, active: t.active,
    })),
  });
});
app.patch("/api/admin/tasks/:id", requireAuth, requireAdmin, async (req, res) => {
  const { title, targetValue, rewardCoins, rewardItemCategory, rewardItemName, rewardItemDays, active } = req.body;
  const fields = []; const params = []; let i = 1;
  if (title !== undefined) { fields.push(`title = $${i++}`); params.push(title); }
  if (targetValue !== undefined) { fields.push(`targetValue = $${i++}`); params.push(targetValue); }
  if (rewardCoins !== undefined) { fields.push(`rewardCoins = $${i++}`); params.push(rewardCoins); }
  if (rewardItemCategory !== undefined) { fields.push(`rewardItemCategory = $${i++}`); params.push(rewardItemCategory); }
  if (rewardItemName !== undefined) { fields.push(`rewardItemName = $${i++}`); params.push(rewardItemName); }
  if (rewardItemDays !== undefined) { fields.push(`rewardItemDays = $${i++}`); params.push(rewardItemDays); }
  if (active !== undefined) { fields.push(`active = $${i++}`); params.push(active); }
  if (fields.length === 0) return res.status(400).json({ error: "Nothing to update" });
  params.push(Number(req.params.id));
  await query(`UPDATE TaskDefinitions SET ${fields.join(", ")} WHERE id = $${i}`, params);
  res.json({ message: "Task updated" });
});
app.post("/api/admin/tasks/toggle", requireAuth, requireAdmin, async (req, res) => {
  const { enabled } = req.body;
  await setAppSetting("newuser_task_enabled", enabled);
  res.json({ message: "Updated" });
});
app.post("/api/admin/tasks/bonus", requireAuth, requireAdmin, async (req, res) => {
  const { bonusCoins } = req.body;
  if (!Number.isInteger(bonusCoins) || bonusCoins < 0) return res.status(400).json({ error: "bonusCoins must be a non-negative integer" });
  await setAppSetting("task_bonus_coins", bonusCoins);
  res.json({ message: "Bonus updated" });
});
// % of users who started the 7-Day Task and completed each day's tasks -
// gives Admin a simple funnel: how many drop off at each day.
app.get("/api/admin/tasks/stats", requireAuth, requireAdmin, async (req, res) => {
  const startedResult = await query("SELECT COUNT(*) FROM Users WHERE taskStartAt IS NOT NULL");
  const started = Number(startedResult.rows[0].count);
  const stats = [];
  for (let day = 1; day <= 7; day++) {
    const dayDefs = await query("SELECT id FROM TaskDefinitions WHERE day = $1 AND active = TRUE", [day]);
    const defIds = dayDefs.rows.map((r) => r.id);
    if (defIds.length === 0) { stats.push({ day, pctCompleted: 0 }); continue; }
    const completedResult = await query(
      `SELECT COUNT(*) FROM (
         SELECT userId FROM UserTaskProgress WHERE taskDefId = ANY($1) AND claimed = TRUE
         GROUP BY userId HAVING COUNT(DISTINCT taskDefId) = $2
       ) sub`,
      [defIds, defIds.length]
    );
    const completed = Number(completedResult.rows[0].count);
    stats.push({ day, completedCount: completed, pctCompleted: started > 0 ? Math.round((completed / started) * 100) : 0 });
  }
  const allDoneResult = await query("SELECT COUNT(*) FROM Transactions WHERE type = 'task_reward' AND meta->>'bonus' = 'true'");
  res.json({ usersStarted: started, dayStats: stats, usersCompletedAll: Number(allDoneResult.rows[0].count) });
});


// =================================================================
// FAMILY SYSTEM - house chat, contributions, level (cosmetics only)
// =================================================================
const FAMILY_CREATE_COST = 1000000; // no exact figure was given - this is a placeholder, easy to change here
const FAMILY_MAX_MEMBERS = 50;
const FAMILY_PALETTE = [
  "#CD7F32", "#C0C0C0", "#FFD700", "#E5E4E2", "#22D3EE", "#FBBF24", "#800080", "#DC143C",
  "#FF8C00", "#8B5CF6", "#FDE68A", "#4682B4", "#111827", "#C4B5FD", "#FFFFFF", "#4A148C",
  "#FF5722", "#3F51B5", "#EC4899", "linear-gradient(135deg,#F59E0B,#EC4899,#8B5CF6)",
];
async function getFamilyTiers() {
  const result = await query("SELECT * FROM FamilyLevelTiers ORDER BY tierStart ASC");
  return result.rows.map((r, i) => ({
    tierStart: r.tierstart,
    tierEnd: r.tierend,
    threshold: Number(r.threshold),
    name: r.title,
    colorHex: FAMILY_PALETTE[i] || "#94A3B8",
    effect: r.badgename,
    badgeName: r.badgename,
    coverName: r.covername,
  }));
}
async function getMyFamilyMembership(userId) {
  const r = await query("SELECT * FROM FamilyMembers WHERE userId = $1", [userId]);
  return r.rows[0] || null;
}
// Called whenever a gift is sent anywhere in the app - credits the sender's
// family (if any), posts the "+X to Family" line, and announces level-ups.
async function creditFamilyContribution(userId, coinCost, contextLabel) {
  const membership = await getMyFamilyMembership(userId);
  if (!membership) return;
  const familyResult = await query("SELECT * FROM Families WHERE id = $1", [membership.familyid]);
  const family = familyResult.rows[0];
  if (!family) return;
  const before = Number(family.totalcoins);
  const after = before + coinCost;
  await query("UPDATE Families SET totalCoins = totalCoins + $1 WHERE id = $2", [coinCost, family.id]);
  await query("UPDATE FamilyMembers SET contributedCoins = contributedCoins + $1 WHERE familyId = $2 AND userId = $3", [
    coinCost, family.id, userId,
  ]);
  const userResult = await query("SELECT username FROM Users WHERE id = $1", [userId]);
  const username = userResult.rows[0].username;
  await query("INSERT INTO FamilyMessages (familyId, content, isSystem) VALUES ($1,$2,TRUE)", [
    family.id, `${username} sent a ${coinCost.toLocaleString()} coin gift${contextLabel ? " " + contextLabel : ""}. +${coinCost.toLocaleString()} to Family`,
  ]);
  const tiers = await getFamilyTiers();
  const beforeStatus = computeLevelStatus(before, tiers);
  const afterStatus = computeLevelStatus(after, tiers);
  if (afterStatus.level > beforeStatus.level) {
    const unlockedNew = afterStatus.name !== beforeStatus.name;
    await query("INSERT INTO FamilyMessages (familyId, content, isSystem) VALUES ($1,$2,TRUE)", [
      family.id,
      unlockedNew
        ? `Family level up! Lv.${beforeStatus.level} -> Lv.${afterStatus.level}. ${afterStatus.name} - ${afterStatus.effect} unlocked!`
        : `Family level up! Lv.${beforeStatus.level} -> Lv.${afterStatus.level}.`,
    ]);
  }
}

app.post("/api/family/create", requireAuth, async (req, res) => {
  const { name } = req.body;
  if (!name || name.trim().length < 3) return res.status(400).json({ error: "Family name must be at least 3 characters" });
  const existing = await getMyFamilyMembership(req.user.id);
  if (existing) return res.status(400).json({ error: "You're already in a family. Leave it first." });
  const walletResult = await query("SELECT coinBalance FROM Wallets WHERE userId = $1", [req.user.id]);
  if (!walletResult.rows[0] || walletResult.rows[0].coinbalance < FAMILY_CREATE_COST) {
    return res.status(400).json({ error: `Creating a family costs ${FAMILY_CREATE_COST.toLocaleString()} coins` });
  }
  const nameClash = await query("SELECT id FROM Families WHERE name = $1", [name.trim()]);
  if (nameClash.rows.length > 0) return res.status(409).json({ error: "That family name is taken" });
  await query("UPDATE Wallets SET coinBalance = coinBalance - $1 WHERE userId = $2", [FAMILY_CREATE_COST, req.user.id]);
  await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1,'purchase',$2,$3)", [
    req.user.id, -FAMILY_CREATE_COST, JSON.stringify({ note: "Family creation fee" }),
  ]);
  const familyResult = await query("INSERT INTO Families (name, headUserId) VALUES ($1,$2) RETURNING id", [name.trim(), req.user.id]);
  await query("INSERT INTO FamilyMembers (familyId, userId, role) VALUES ($1,$2,'head')", [familyResult.rows[0].id, req.user.id]);
  res.json({ message: "Family created", familyId: familyResult.rows[0].id });
});

app.get("/api/family/list", requireAuth, async (req, res) => {
  const tiers = await getFamilyTiers();
  const result = await query(
    `SELECT f.id, f.name, f.totalCoins, (SELECT COUNT(*) FROM FamilyMembers fm WHERE fm.familyId = f.id) AS memberCount
     FROM Families f ORDER BY f.totalCoins DESC LIMIT 100`
  );
  res.json({
    families: result.rows.map((r) => {
      const status = computeLevelStatus(Number(r.totalcoins), tiers);
      return { id: r.id, name: r.name, memberCount: Number(r.membercount), level: status.level, title: status.name, badgeName: status.effect, colorHex: status.colorHex };
    }),
  });
});

app.get("/api/family/mine", requireAuth, async (req, res) => {
  const membership = await getMyFamilyMembership(req.user.id);
  if (!membership) return res.json({ inFamily: false });
  const familyResult = await query("SELECT * FROM Families WHERE id = $1", [membership.familyid]);
  const family = familyResult.rows[0];
  const tiers = await getFamilyTiers();
  const status = computeLevelStatus(Number(family.totalcoins), tiers);
  const membersResult = await query(
    `SELECT fm.userId, fm.role, fm.contributedCoins, u.username, u.prettyId FROM FamilyMembers fm
     JOIN Users u ON u.id = fm.userId WHERE fm.familyId = $1 ORDER BY fm.contributedCoins DESC`,
    [family.id]
  );
  res.json({
    inFamily: true,
    family: { id: family.id, name: family.name, headUserId: family.headuserid, totalCoins: Number(family.totalcoins), selectedCoverTier: family.selectedcovertier },
    status,
    myRole: membership.role,
    members: membersResult.rows.map((m) => ({
      userId: m.userid, username: m.username, prettyId: m.prettyid, role: m.role, contributedCoins: Number(m.contributedcoins),
    })),
  });
});

app.post("/api/family/:id/apply", requireAuth, async (req, res) => {
  const familyId = Number(req.params.id);
  const existing = await getMyFamilyMembership(req.user.id);
  if (existing) return res.status(400).json({ error: "You're already in a family" });
  const dup = await query("SELECT id FROM FamilyApplications WHERE familyId = $1 AND userId = $2 AND status = 'pending'", [familyId, req.user.id]);
  if (dup.rows.length > 0) return res.status(400).json({ error: "You already applied - waiting for a response" });
  await query("INSERT INTO FamilyApplications (familyId, userId) VALUES ($1,$2)", [familyId, req.user.id]);
  const headResult = await query("SELECT headUserId FROM Families WHERE id = $1", [familyId]);
  if (headResult.rows[0]) {
    await query("INSERT INTO SystemMessages (userId, type, content) VALUES ($1,'task',$2)", [
      headResult.rows[0].headuserid, "A user wants to join your family. Review it in Family > Applications.",
    ]);
  }
  res.json({ message: "Application submitted" });
});

app.get("/api/family/applications", requireAuth, async (req, res) => {
  const membership = await getMyFamilyMembership(req.user.id);
  if (!membership || !["head", "admin"].includes(membership.role)) return res.status(403).json({ error: "Only the Family Head or an Admin can view applications" });
  const result = await query(
    `SELECT a.id, a.userId, u.username, u.prettyId, a.createdAt FROM FamilyApplications a
     JOIN Users u ON u.id = a.userId WHERE a.familyId = $1 AND a.status = 'pending' ORDER BY a.createdAt ASC`,
    [membership.familyid]
  );
  res.json({ applications: result.rows.map((r) => ({ id: r.id, userId: r.userid, username: r.username, prettyId: r.prettyid, createdAt: r.createdat })) });
});

app.post("/api/family/applications/:id/respond", requireAuth, async (req, res) => {
  const membership = await getMyFamilyMembership(req.user.id);
  if (!membership || !["head", "admin"].includes(membership.role)) return res.status(403).json({ error: "Only the Family Head or an Admin can respond" });
  const { accept } = req.body;
  const appResult = await query("SELECT * FROM FamilyApplications WHERE id = $1 AND familyId = $2 AND status = 'pending'", [
    Number(req.params.id), membership.familyid,
  ]);
  if (appResult.rows.length === 0) return res.status(404).json({ error: "Application not found" });
  const application = appResult.rows[0];
  await query("UPDATE FamilyApplications SET status = $1 WHERE id = $2", [accept ? "accepted" : "rejected", application.id]);
  if (accept) {
    const countResult = await query("SELECT COUNT(*) FROM FamilyMembers WHERE familyId = $1", [membership.familyid]);
    if (Number(countResult.rows[0].count) >= FAMILY_MAX_MEMBERS) return res.status(400).json({ error: "This family is full (50/50)" });
    const already = await getMyFamilyMembership(application.userid);
    if (already) return res.status(400).json({ error: "That user already joined another family" });
    await query("INSERT INTO FamilyMembers (familyId, userId) VALUES ($1,$2)", [membership.familyid, application.userid]);
  }
  res.json({ message: accept ? "Member accepted" : "Application rejected" });
});

app.post("/api/family/:id/invite", requireAuth, async (req, res) => {
  const familyId = Number(req.params.id);
  const membership = await getMyFamilyMembership(req.user.id);
  if (!membership || membership.familyid !== familyId || !["head", "admin"].includes(membership.role)) {
    return res.status(403).json({ error: "Only the Family Head or an Admin can invite" });
  }
  const { userId } = req.body;
  const already = await getMyFamilyMembership(userId);
  if (already) return res.status(400).json({ error: "That user is already in a family" });
  const countResult = await query("SELECT COUNT(*) FROM FamilyMembers WHERE familyId = $1", [familyId]);
  if (Number(countResult.rows[0].count) >= FAMILY_MAX_MEMBERS) return res.status(400).json({ error: "This family is full (50/50)" });
  await query("INSERT INTO FamilyMembers (familyId, userId) VALUES ($1,$2)", [familyId, userId]);
  await query("INSERT INTO SystemMessages (userId, type, content) VALUES ($1,'task','You were added to a family.')", [userId]);
  res.json({ message: "Member invited" });
});

app.post("/api/family/leave", requireAuth, async (req, res) => {
  const membership = await getMyFamilyMembership(req.user.id);
  if (!membership) return res.status(400).json({ error: "You're not in a family" });
  if (membership.role === "head") {
    const others = await query("SELECT userId FROM FamilyMembers WHERE familyId = $1 AND userId != $2 ORDER BY contributedCoins DESC LIMIT 1", [
      membership.familyid, req.user.id,
    ]);
    if (others.rows.length > 0) {
      await query("UPDATE FamilyMembers SET role = 'head' WHERE familyId = $1 AND userId = $2", [membership.familyid, others.rows[0].userid]);
      await query("UPDATE Families SET headUserId = $1 WHERE id = $2", [others.rows[0].userid, membership.familyid]);
    } else {
      await query("DELETE FROM Families WHERE id = $1", [membership.familyid]);
    }
  }
  await query("DELETE FROM FamilyMembers WHERE familyId = $1 AND userId = $2", [membership.familyid, req.user.id]);
  res.json({ message: "You left the family" });
});

app.get("/api/family/chat", requireAuth, async (req, res) => {
  const membership = await getMyFamilyMembership(req.user.id);
  if (!membership) return res.status(403).json({ error: "Join a family to see its house chat" });
  const result = await query(
    `SELECT fm.*, u.username, g.name AS giftName FROM FamilyMessages fm
     LEFT JOIN Users u ON u.id = fm.userId LEFT JOIN Gifts g ON g.id = fm.giftId
     WHERE fm.familyId = $1 ORDER BY fm.createdAt ASC LIMIT 200`,
    [membership.familyid]
  );
  res.json({
    messages: result.rows.map((r) => ({
      id: r.id, userId: r.userid, username: r.username, content: r.content, giftName: r.giftname, isSystem: r.issystem, createdAt: r.createdat,
    })),
  });
});
app.post("/api/family/chat", requireAuth, async (req, res) => {
  const membership = await getMyFamilyMembership(req.user.id);
  if (!membership) return res.status(403).json({ error: "Join a family to chat here" });
  const { content, giftId } = req.body;
  if (!content && !giftId) return res.status(400).json({ error: "content or giftId is required" });
  if (giftId) {
    const walletResult = await query("SELECT coinBalance FROM Wallets WHERE userId = $1", [req.user.id]);
    const giftResult = await query("SELECT id, name, coinCost, receiverSplitPct FROM Gifts WHERE id = $1", [giftId]);
    if (giftResult.rows.length === 0) return res.status(404).json({ error: "Gift not found" });
    const gift = giftResult.rows[0];
    if (!walletResult.rows[0] || walletResult.rows[0].coinbalance < gift.coincost) return res.status(400).json({ error: "Insufficient coins" });
    await query("UPDATE Wallets SET coinBalance = coinBalance - $1 WHERE userId = $2", [gift.coincost, req.user.id]);
    await query("INSERT INTO Transactions (userId, type, amount, meta) VALUES ($1,'gift_sent',$2,$3)", [
      req.user.id, -gift.coincost, JSON.stringify({ giftName: gift.name, via: "family" }),
    ]);
    await creditFamilyContribution(req.user.id, gift.coincost, "in the Family House");
  }
  await query("INSERT INTO FamilyMessages (familyId, userId, content, giftId) VALUES ($1,$2,$3,$4)", [
    membership.familyid, req.user.id, content || null, giftId || null,
  ]);
  res.json({ message: "Sent" });
});

app.get("/api/family/ranking", requireAuth, async (req, res) => {
  const membership = await getMyFamilyMembership(req.user.id);
  if (!membership) return res.status(403).json({ error: "Join a family to see its ranking" });
  const result = await query(
    `SELECT u.username, u.prettyId, fm.role, fm.contributedCoins FROM FamilyMembers fm
     JOIN Users u ON u.id = fm.userId WHERE fm.familyId = $1 ORDER BY fm.contributedCoins DESC`,
    [membership.familyid]
  );
  res.json({ ranking: result.rows.map((r) => ({ username: r.username, prettyId: r.prettyid, role: r.role, contributedCoins: Number(r.contributedcoins) })) });
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
app.patch("/api/levels/:kind/:tierStart", requireAuth, requireAdmin, async (req, res) => {
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
app.patch("/api/vip/levels/:level", requireAuth, requireAdmin, async (req, res) => {
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
    verifiedType: row.verifiedtype || "none",
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
  SELECT m.*, u.username, u.prettyId, u.agencyId, u.isHostBadge, u.isDbBadge, u.phoneVerified, u.verifiedType,
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
      const result = await sendGiftOrSpin({ senderId: user.id, streamId, giftId });
      if (result.isLuckyWheel) {
        io.to(streamKey).emit("lucky-wheel-result", {
          fromUsername: user.username,
          giftName: result.giftName,
          icon: result.icon,
          coinCost: result.coinCost,
          multiplier: result.multiplier,
          payout: result.payout,
          receiverDiamonds: result.receiverDiamonds,
        });
      } else {
        io.to(streamKey).emit("gift-received", {
          fromUsername: user.username,
          giftName: result.giftName,
          icon: result.icon,
          coinCost: result.coinCost,
        });
      }
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
