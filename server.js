/**
 * server.js (FULL) - users.json + session cookie + admin key
 *
 * Routes:
 *  GET  /                 -> OK
 *  GET  /auth/me          -> { loggedIn, username }
 *  POST /auth/login       -> login
 *  POST /auth/logout      -> logout
 *
 *  GET  /api/announcements
 *  POST /api/summarize
 *
 *  GET    /admin/users    -> list users (requires X-Admin-Key)
 *  POST   /admin/users    -> add user  (requires X-Admin-Key)
 *  DELETE /admin/users/:username -> delete user (requires X-Admin-Key)
 */

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const axios = require("axios");
const cheerio = require("cheerio");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");
const { GoogleGenerativeAI } = require("@google/generative-ai");

const app = express();
app.use(express.json({ limit: "2mb" }));

// ===================== ENV =====================
const PORT = process.env.PORT || 3000;

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
if (!GEMINI_API_KEY) {
  console.error("❌ Missing GEMINI_API_KEY");
  process.exit(1);
}

const ADMIN_KEY = process.env.ADMIN_KEY || ""; // สำคัญ: ใช้คีย์นี้เรียก /admin/*
if (!ADMIN_KEY) {
  console.warn("⚠️ ADMIN_KEY is empty. /admin/* will be unsafe. Set ADMIN_KEY in env.");
}

const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || ""; // เช่น https://username.github.io
// ถ้าไม่ตั้ง จะปล่อย * (แต่ cross-site cookie จะไม่เวิร์กกับ '*') — แนะนำตั้งให้ชัด

// ===================== CORS (ต้องรองรับ cookie) =====================
app.use(
  cors({
    origin: (origin, cb) => {
      // รองรับการทดสอบด้วย curl/postman ที่ origin ว่าง
      if (!origin) return cb(null, true);

      if (!ALLOWED_ORIGIN) return cb(null, true);
      if (origin.startsWith(ALLOWED_ORIGIN)) return cb(null, true);

      return cb(new Error("CORS blocked: " + origin));
    },
    credentials: true,
  })
);

// ===================== Cookie Parser แบบง่าย (ไม่ใช้ lib) =====================
function parseCookies(req) {
  const header = req.headers.cookie || "";
  const out = {};
  header.split(";").forEach((part) => {
    const [k, ...v] = part.trim().split("=");
    if (!k) return;
    out[k] = decodeURIComponent(v.join("=") || "");
  });
  return out;
}

function setCookie(res, name, value, opts = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];

  if (opts.httpOnly) parts.push("HttpOnly");
  if (opts.secure) parts.push("Secure");
  if (opts.sameSite) parts.push(`SameSite=${opts.sameSite}`);
  if (opts.path) parts.push(`Path=${opts.path}`);
  if (typeof opts.maxAge === "number") parts.push(`Max-Age=${opts.maxAge}`);

  // cross-site cookie ต้อง SameSite=None + Secure
  res.setHeader("Set-Cookie", parts.join("; "));
}

// ===================== Sessions (Memory) =====================
const sessions = new Map(); // sid -> { username, exp }
const SESSION_TTL_MS = 1000 * 60 * 60 * 12; // 12 ชั่วโมง

function createSID() {
  return crypto.randomBytes(24).toString("hex");
}

function requireAuth(req, res, next) {
  const cookies = parseCookies(req);
  const sid = cookies.sid;
  if (!sid) return res.status(401).json({ error: "Not logged in" });

  const s = sessions.get(sid);
  if (!s) return res.status(401).json({ error: "Session invalid" });

  if (Date.now() > s.exp) {
    sessions.delete(sid);
    return res.status(401).json({ error: "Session expired" });
  }

  // refresh sliding expiration
  s.exp = Date.now() + SESSION_TTL_MS;
  req.user = { username: s.username };
  next();
}

// ===================== Admin Key Gate =====================
function requireAdminKey(req, res, next) {
  const key = req.headers["x-admin-key"];
  if (!ADMIN_KEY) return res.status(500).json({ error: "ADMIN_KEY not set" });
  if (key !== ADMIN_KEY) return res.status(403).json({ error: "Forbidden" });
  next();
}

// ===================== Rate Limit (กันเดารหัส) =====================
const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10, // 10 ครั้ง/นาที ต่อ IP
  standardHeaders: true,
  legacyHeaders: false,
});

// ===================== users.json Storage =====================
const USERS_PATH = path.join(__dirname, "users.json");

// simple mutex to avoid race write
let writing = Promise.resolve();
function withWriteLock(fn) {
  writing = writing.then(fn, fn);
  return writing;
}

function readUsers() {
  if (!fs.existsSync(USERS_PATH)) return [];
  const raw = fs.readFileSync(USERS_PATH, "utf8");
  const json = JSON.parse(raw || "[]");
  if (!Array.isArray(json)) return [];
  return json;
}

function writeUsers(users) {
  const tmp = USERS_PATH + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(users, null, 2), "utf8");
  fs.renameSync(tmp, USERS_PATH);
}

function ensureBootstrapUser() {
  if (fs.existsSync(USERS_PATH)) return;

  const BOOTSTRAP_USER = process.env.BOOTSTRAP_USER || "admin";
  const BOOTSTRAP_PASS = process.env.BOOTSTRAP_PASS || "admin1234"; // เปลี่ยนทันทีหลัง deploy

  const hash = bcrypt.hashSync(BOOTSTRAP_PASS, 10);
  const users = [{ username: BOOTSTRAP_USER, password_hash: hash, created_at: new Date().toISOString() }];

  writeUsers(users);
  console.log("✅ users.json created with bootstrap user:", BOOTSTRAP_USER);
}
ensureBootstrapUser();

// ===================== Health =====================
app.get("/", (req, res) => res.status(200).send("OK: Backend running"));

// ===================== Auth APIs =====================
app.get("/auth/me", (req, res) => {
  const cookies = parseCookies(req);
  const sid = cookies.sid;
  const s = sid ? sessions.get(sid) : null;
  if (!s || Date.now() > s.exp) return res.json({ loggedIn: false });
  return res.json({ loggedIn: true, username: s.username });
});

app.post("/auth/login", loginLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "Missing username/password" });

  const users = readUsers();
  const u = users.find((x) => x.username === username);
  if (!u) return res.status(401).json({ error: "Invalid credentials" });

  const ok = await bcrypt.compare(password, u.password_hash);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  const sid = createSID();
  sessions.set(sid, { username, exp: Date.now() + SESSION_TTL_MS });

  setCookie(res, "sid", sid, {
    httpOnly: true,
    secure: true,      // Render เป็น https อยู่แล้ว
    sameSite: "None",  // เพราะ GitHub Pages เป็นคนละโดเมน
    path: "/",
    maxAge: Math.floor(SESSION_TTL_MS / 1000),
  });

  res.json({ ok: true, username });
});

app.post("/auth/logout", (req, res) => {
  const cookies = parseCookies(req);
  const sid = cookies.sid;
  if (sid) sessions.delete(sid);

  // delete cookie
  setCookie(res, "sid", "", {
    httpOnly: true,
    secure: true,
    sameSite: "None",
    path: "/",
    maxAge: 0,
  });

  res.json({ ok: true });
});

// ===================== Admin: user management =====================
// list users (no passwords)
app.get("/admin/users", requireAuth, requireAdminKey, (req, res) => {
  const users = readUsers().map((u) => ({ username: u.username, created_at: u.created_at }));
  res.json(users);
});

// add user
app.post("/admin/users", requireAuth, requireAdminKey, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "Missing username/password" });
  if (typeof username !== "string" || username.length < 3) return res.status(400).json({ error: "Username too short" });
  if (typeof password !== "string" || password.length < 6) return res.status(400).json({ error: "Password too short (>=6)" });

  await withWriteLock(async () => {
    const users = readUsers();
    if (users.some((u) => u.username === username)) {
      throw Object.assign(new Error("User exists"), { code: 409 });
    }
    const hash = await bcrypt.hash(password, 10);
    users.push({ username, password_hash: hash, created_at: new Date().toISOString() });
    writeUsers(users);
  }).then(
    () => res.json({ ok: true }),
    (err) => {
      if (err.code === 409) return res.status(409).json({ error: "User already exists" });
      console.error(err);
      return res.status(500).json({ error: "Failed to add user" });
    }
  );
});

// delete user by username
app.delete("/admin/users/:username", requireAuth, requireAdminKey, async (req, res) => {
  const uname = req.params.username;
  await withWriteLock(async () => {
    const users = readUsers();
    const next = users.filter((u) => u.username !== uname);
    if (next.length === users.length) {
      throw Object.assign(new Error("Not found"), { code: 404 });
    }
    writeUsers(next);
  }).then(
    () => res.json({ ok: true }),
    (err) => {
      if (err.code === 404) return res.status(404).json({ error: "User not found" });
      console.error(err);
      return res.status(500).json({ error: "Failed to delete user" });
    }
  );
});

// ===================== Existing Features: RAM Cache for summarize =====================
const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);

let memoryCache = {};
const CACHE_TTL_MS = 1000 * 60 * 60 * 24 * 7;

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of Object.entries(memoryCache)) {
    if (v?.ts && now - v.ts > CACHE_TTL_MS) delete memoryCache[k];
  }
}, 1000 * 60 * 30);

function safeUrl(u) {
  try { return encodeURI(u); } catch { return u; }
}
function isPdfUrl(url) {
  return typeof url === "string" && url.toLowerCase().endsWith(".pdf");
}

// ===================== Protected APIs =====================
app.get("/api/announcements", requireAuth, async (req, res) => {
  try {
    const { data } = await axios.get("https://help.mypurecloud.com/announcements/", {
      headers: { "User-Agent": "Mozilla/5.0" },
      timeout: 30000,
    });

    const $ = cheerio.load(data);
    const announcements = [];
    const seen = new Set();

    $("table tbody tr").each((index, element) => {
      const tds = $(element).find("td");
      let link = $(tds[0]).find("a").attr("href");

      if (link && !link.startsWith("http")) link = "https://help.mypurecloud.com" + link;

      const textDetails = $(tds[0]).text().trim();
      const uniqueKey = link && link !== "#" ? link : textDetails;

      if (seen.has(uniqueKey)) return;
      seen.add(uniqueKey);

      let item = null;
      if (tds.length >= 4) {
        item = {
          id: index,
          details: textDetails,
          link: link,
          type: $(tds[1]).text().trim(),
          announcedDate: $(tds[2]).text().trim(),
          effectiveDate: $(tds[3]).text().trim(),
        };
      } else if (tds.length === 3) {
        item = {
          id: index,
          details: textDetails,
          link: link,
          type: "-",
          announcedDate: $(tds[1]).text().trim(),
          effectiveDate: $(tds[2]).text().trim(),
        };
      }

      if (item) {
        const cachedData = link ? memoryCache[link] : null;
        item.hasSummary = !!cachedData;
        item.cachedImportance = cachedData ? cachedData.importance : null;
        announcements.push(item);
      }
    });

    res.json(announcements);
  } catch (error) {
    console.error("❌ /api/announcements error:", error.message);
    res.status(500).json({ error: "Failed to fetch data" });
  }
});

app.post("/api/summarize", requireAuth, async (req, res) => {
  const { url, forceRefresh, selectedModel } = req.body || {};
  if (!url) return res.status(400).json({ summary: "❌ Missing url", importance: "LOW" });
  if (isPdfUrl(url)) return res.json({ summary: "⚠️ ไม่สามารถสรุปไฟล์ PDF ได้", importance: "LOW" });

  if (memoryCache[url] && !forceRefresh) {
    return res.json({
      summary: memoryCache[url].summary,
      importance: memoryCache[url].importance || "MEDIUM",
      fromCache: true,
    });
  }

  try {
    const modelName = selectedModel || "gemma-3-27b-it";
    const model = genAI.getGenerativeModel({ model: modelName });

    const encodedUrl = safeUrl(url);
    const { data } = await axios.get(encodedUrl, {
      headers: { "User-Agent": "Mozilla/5.0" },
      timeout: 30000,
    });

    const $ = cheerio.load(data);
    $("script, style, nav, header, footer, .sidebar, .menu, .breadcrumb, .cookie-consent, [role='navigation']").remove();

    let text = $(".entry-content").text() || $("article").text() || $("body").text();
    text = text.replace(/\s\s+/g, " ").trim().substring(0, 15000);

    const prompt = `
Role: IT Support (Genesys Cloud Admin).
Task:
1) Analyze impact level for production contact center operations as one of: HIGH, MEDIUM, LOW.
2) Write a formal Thai email to internal stakeholders. Keep it clear and actionable.
3) If this is a deprecation/removal/pricing/billing/security change, impact should likely be HIGH.

Output Format EXACTLY:
[IMP:HIGH|MEDIUM|LOW]
Subject: ...

Body: (Thai formal email, bullet points allowed)

Content:
${text}
`;

    const result = await model.generateContent(prompt);
    const response = await result.response;
    let fullText = (response.text() || "").trim();

    let importance = "MEDIUM";
    let summary = fullText;

    const impMatch = fullText.match(/^\[IMP:(HIGH|MEDIUM|LOW)\]/i);
    if (impMatch) {
      importance = impMatch[1].toUpperCase();
      summary = fullText.replace(impMatch[0], "").trim();
    }

    memoryCache[url] = { summary, importance, ts: Date.now() };
    res.json({ summary, importance, fromCache: false });
  } catch (error) {
    console.error("❌ /api/summarize error:", error.message);
    res.status(500).json({ summary: "❌ Error: " + error.message, importance: "LOW" });
  }
});

// ===================== Start =====================
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
