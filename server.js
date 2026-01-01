/**
 * server.js
 * Genesys Cloud Email Helper - Backend
 *
 * - GET  /api/announcements : scrape announcements list
 * - POST /api/summarize     : summarize + impact importance via Gemini/Gemma (RAM cache)
 */

require("dotenv").config();

const express = require("express");
const axios = require("axios");
const cheerio = require("cheerio");
const cors = require("cors");
const { GoogleGenerativeAI } = require("@google/generative-ai");

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

// ======================================================
// ENV
// ======================================================
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
if (!GEMINI_API_KEY) {
  console.error("❌ Missing GEMINI_API_KEY in .env");
  process.exit(1);
}

const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);

// ======================================================
// RAM Cache (no file write)
// ======================================================
/**
 * memoryCache[url] = { summary, importance, ts }
 */
let memoryCache = {};
const CACHE_TTL_MS = 1000 * 60 * 60 * 24 * 7; // 7 days TTL (ปรับได้)

// cleanup cache (optional)
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of Object.entries(memoryCache)) {
    if (!v?.ts) continue;
    if (now - v.ts > CACHE_TTL_MS) delete memoryCache[k];
  }
}, 1000 * 60 * 30);

// ======================================================
// Helpers
// ======================================================
function safeUrl(u) {
  try {
    return encodeURI(u);
  } catch {
    return u;
  }
}

function isPdfUrl(url) {
  return typeof url === "string" && url.toLowerCase().endsWith(".pdf");
}

// ======================================================
// API 1: Fetch List
// ======================================================
app.get("/api/announcements", async (req, res) => {
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

// ======================================================
// API 2: Summarize + Analyze Importance (RAM Only)
// ======================================================
app.post("/api/summarize", async (req, res) => {
  const { url, forceRefresh, selectedModel } = req.body || {};

  if (!url) return res.status(400).json({ summary: "❌ Missing url", importance: "LOW" });
  if (isPdfUrl(url)) return res.json({ summary: "⚠️ ไม่สามารถสรุปไฟล์ PDF ได้", importance: "LOW" });

  // RAM cache
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

    console.log(`🧠 Analyzing: ${url} with ${modelName}`);

    const encodedUrl = safeUrl(url);
    const { data } = await axios.get(encodedUrl, {
      headers: { "User-Agent": "Mozilla/5.0" },
      timeout: 30000,
    });

    const $ = cheerio.load(data);

    // remove noisy elements
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

    // save to RAM
    memoryCache[url] = { summary, importance, ts: Date.now() };

    res.json({ summary, importance, fromCache: false });
  } catch (error) {
    console.error("❌ /api/summarize error:", error.message);
    res.status(500).json({ summary: "❌ Error: " + error.message, importance: "LOW" });
  }
});

// ======================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on http://localhost:${PORT}`));
