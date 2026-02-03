// server.js
// Simple Express backend that:
//  - Accepts POST /api/scan { urls: [ ... ] }
//  - For each URL, queries Cisco Talos + FortiGuard
//  - Returns a combined verdict per URL

import express from "express";
import fetch from "node-fetch"; // npm install express node-fetch

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

// TODO: set these from env vars / config
const TALOS_API_URL = process.env.TALOS_API_URL || "https://<your-talos-endpoint>";
const TALOS_API_KEY = process.env.TALOS_API_KEY || "";
const FORTIGUARD_API_URL = process.env.FORTIGUARD_API_URL || "https://<your-fortiguard-endpoint>";
const FORTIGUARD_API_KEY = process.env.FORTIGUARD_API_KEY || "";

// --- Helpers to call external services ---
// NOTE: You must replace the body/headers/URL formats with the ones from
// Cisco Talos and FortiGuard official documentation.

async function queryTalos(url) {
  if (!TALOS_API_URL) return null;

  try {
    // Example shape – adjust to real Talos API spec
    const res = await fetch(TALOS_API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(TALOS_API_KEY ? { "Authorization": `Bearer ${TALOS_API_KEY}` } : {})
      },
      body: JSON.stringify({ url })
    });

    if (!res.ok) {
      console.error("Talos error", res.status);
      return null;
    }

    const data = await res.json();
    // Map to a normalized structure
    return {
      category: data.category || data.threat_category || null,
      score: data.score || data.reputation_score || null,
      raw: data
    };
  } catch (err) {
    console.error("Talos request failed", err);
    return null;
  }
}

async function queryFortiGuard(url) {
  if (!FORTIGUARD_API_URL) return null;

  try {
    // Example shape – adjust to real FortiGuard Web Filter API spec
    const res = await fetch(FORTIGUARD_API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(FORTIGUARD_API_KEY ? { "Authorization": `Bearer ${FORTIGUARD_API_KEY}` } : {})
      },
      body: JSON.stringify({ url })
    });

    if (!res.ok) {
      console.error("FortiGuard error", res.status);
      return null;
    }

    const data = await res.json();
    return {
      category: data.category || data.webfilter_category || null,
      threat: data.threat || data.threat_level || null,
      raw: data
    };
  } catch (err) {
    console.error("FortiGuard request failed", err);
    return null;
  }
}

// --- Policy logic: map categories → blocked / review / good / unknown ---

function classifyFromEngines(url, talos, forti) {
  const categories = [];
  const lowerUrl = url.toLowerCase();

  if (talos && talos.category) categories.push(String(talos.category).toLowerCase());
  if (forti && forti.category) categories.push(String(forti.category).toLowerCase());
  if (forti && forti.threat) categories.push(String(forti.threat).toLowerCase());

  const catString = categories.join(" | ");

  const blockedSignals = [
    "adult", "porn", "sex", "nsfw", "gore", "violence",
    "malware", "phishing", "botnet", "spam", "hacking"
  ];

  const reviewSignals = [
    "games", "game", "social", "social networking", "chat",
    "streaming", "video", "entertainment", "proxy", "vpn"
  ];

  const goodSignals = [
    "education", "educational", "reference", "academic",
    "business", "productivity", "search engines"
  ];

  const hasBlocked = blockedSignals.some(s => catString.includes(s));
  const hasReview = reviewSignals.some(s => catString.includes(s));
  const hasGood = goodSignals.some(s => catString.includes(s));

  let status = "unknown";
  let label = "Unsure";
  let reason = "No strong policy signals from Talos/FortiGuard categories.";

  if (hasBlocked) {
    status = "blocked";
    label = "Blocked";
    reason = "Talos/FortiGuard category indicates adult, gore, malware, or similar high‑risk content.";
  } else if (hasReview) {
    status = "review";
    label = "Needs review";
    reason = "Talos/FortiGuard category indicates games, social, streaming, or proxy‑like content.";
  } else if (hasGood) {
    status = "good";
    label = "Good";
    reason = "Talos/FortiGuard category indicates educational, reference, or productivity content.";
  }

  // Extra safety: if either engine explicitly flags high threat
  if (talos && typeof talos.score === "number" && talos.score < 0) {
    status = "blocked";
    label = "Blocked";
    reason = "Cisco Talos reputation score is negative (high risk).";
  }

  return { status, label, reason };
}

// --- API route ---

app.post("/api/scan", async (req, res) => {
  const urls = Array.isArray(req.body.urls) ? req.body.urls : [];
  if (!urls.length) {
    return res.status(400).json({ error: "No URLs provided.", results: [] });
  }

  const results = [];

  for (const url of urls) {
    try {
      const [talos, fortiguard] = await Promise.all([
        queryTalos(url),
        queryFortiGuard(url)
      ]);

      const verdict = classifyFromEngines(url, talos, fortiguard);

      results.push({
        url,
        status: verdict.status,
        label: verdict.label,
        reason: verdict.reason,
        talos,
        fortiguard
      });
    } catch (err) {
      console.error("Scan failed for URL", url, err);
      results.push({
        url,
        status: "unknown",
        label: "Unsure",
        reason: "Error querying Talos/FortiGuard.",
        talos: null,
        fortiguard: null
      });
    }
  }

  res.json({ results });
});

// Serve static frontend (if you put index.html in ./public)
app.use(express.static("public"));

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
