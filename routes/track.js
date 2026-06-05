const express = require("express");
const router = express.Router();
const Visitor = require("../models/Visitor");
const BlockedIP = require("../models/BlockedIP");
const geoip = require("geoip-lite");
const crypto = require("crypto");

// In-memory IP cache: ip → { blocked, reason, timestamp }
const ipCache = new Map();

// ============ BLOCKLISTS ============

const WHITELIST_ISPS = [
  "CARRIER-NET",
  "TATA Communications",
  "Seacom Limited"
];

const BANNED_ISPS = [
  "CLOUDFLARENET", "Cloudflare, Inc.",
  "Microsoft Azure", "AMAZON-02", "Google Cloud",
  "DIGITALOCEAN-ASN", "OVH SAS", "Hetzner Online GmbH",
  "MAGIC-WAN", "Cogent Communications", "xTom GmbH",
  "Mythic Beasts Ltd", "IVPN", "Oeck LTD",
  "Hide.me VPN", "AdGuard VPN",
  "Bright Data", "Luminati", "Soax", "NetNut",
  "IPRoyal", "Proxy-Cheap", "Smartproxy", "Oxylabs",
  "GeoSurf", "Infatica", "Rayobyte", "PacketStream",
  "Zyte", "ScraperAPI", "ScrapingBee", "ScrapingFish"
];

// Keyword fragments that indicate non-residential ISPs
const bannedKeywords = [
  "hosting", "datacenter", "data center", "server", "vps", "virtual private",
  "dedicated", "cloud", "colocation", "colo", "cdn", "content delivery",
  "vpn", "proxy", "anonymiz", "tunnel", "tor ", "exit node",
  "transit", "backbone", "peering", "security", "firewall", "managed services"
];

const BLOCKED_ASNS = [
  "AS15169", // Google Cloud
  "AS8075",  // Microsoft Azure
  "AS16509", // AWS
  "AS14061", // DigitalOcean
  "AS16276", // OVH
  "AS24940", // Hetzner
  "AS45102", // Alibaba
  "AS31898", // Oracle Cloud
  "AS36351", // SoftLayer/IBM
  "AS63949", // Linode/Akamai
  "AS20473", // Vultr
  "AS136787",// Huawei Cloud
  "AS13414", // Twitter bots
  "AS32934"  // Facebook/Meta bots
];

// ============ HEADLESS BROWSER DETECTION ============

function isHeadlessBrowser(userAgent, headers) {
  const headlessSigns = [
    "HeadlessChrome", "PhantomJS", "Puppeteer",
    "Playwright", "Cypress", "selenium", "webdriver"
  ];

  if (headlessSigns.some(sign => userAgent.includes(sign))) return true;

  const required = ["accept-language", "accept-encoding", "cache-control"];
  const missing = required.filter(h => !headers[h]);
  if (missing.length > 1) return true;

  return false;
}

// ============ BEHAVIORAL RATE LIMITING ============

const requestTracker = new Map();

function analyzeBehavior(ip, path) {
  const now = Date.now();
  const windowMs = 60000;

  if (!requestTracker.has(ip)) {
    requestTracker.set(ip, { requests: [], lastClean: now });
  }

  const record = requestTracker.get(ip);

  if (now - record.lastClean > windowMs) {
    record.requests = [];
    record.lastClean = now;
  }

  record.requests.push({ timestamp: now, path });
  record.requests = record.requests.filter(r => now - r.timestamp < windowMs);

  const count = record.requests.length;
  const uniquePaths = new Set(record.requests.map(r => r.path)).size;

  if (count > 30) return "RATE_LIMIT_EXCEEDED";
  if (count > 10 && uniquePaths === 1) return "REPETITIVE_PATH";
  if (count > 5 && now - record.requests[0]?.timestamp < 3000) return "BURST_REQUEST";

  return null;
}

// ============ ASN LOOKUP ============

async function getASN(ip) {
  try {
    const response = await fetch(`http://ip-api.com/json/${ip}?fields=as`);
    const data = await response.json();
    const match = data.as?.match(/AS(\d+)/);
    return match ? `AS${match[1]}` : null;
  } catch {
    return null;
  }
}

// ============ MAIN ROUTE ============

router.post("/", async (req, res) => {
  try {
    let ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "";
    if (ip.includes(",")) ip = ip.split(",")[0];
    ip = ip.replace("::ffff:", "").trim();

    // --- Cache check ---
    const cached = ipCache.get(ip);
    if (cached && cached.timestamp > Date.now() - 10 * 60 * 1000) {
      if (cached.blocked) {
        return res.status(403).json({ error: cached.reason || "Blocked" });
      }
    }

    // --- Persistent blocklist ---
    const blocked = await BlockedIP.findOne({ ip });
    if (blocked) {
      ipCache.set(ip, { blocked: true, timestamp: Date.now(), reason: blocked.reason });
      return res.status(403).json({ error: "Access denied." });
    }

    const userAgent = req.get("User-Agent") || "";
    const headers = req.headers;
    const path = req.body.path || "/";

    // 1. Headless browser detection
    if (isHeadlessBrowser(userAgent, headers)) {
      await BlockedIP.updateOne({ ip }, { $set: { reason: "Headless browser detected" } }, { upsert: true });
      return res.status(403).json({ error: "Access denied: Automated browser detected" });
    }

    // 2. Behavioral analysis
    const behavior = analyzeBehavior(ip, path);
    if (behavior) {
      await BlockedIP.updateOne({ ip }, { $set: { reason: `Behavioral: ${behavior}` } }, { upsert: true });
      return res.status(429).json({ error: "Too many requests or suspicious pattern" });
    }

    // 3. Bot / scraper user-agent
    const isBot = /bot|crawl|spider|curl|python|fetch|scrapy|wget|httpclient|axios|node-fetch|got|request|urllib|libwww|perl|ruby|java|php/i.test(userAgent);
    const isProxyUA = /proxy|vpn|anonym|tor|hidemy|tunnel|private internet access|nord|express|surfshark|proton|cyberghost|mullvad|windscribe/i.test(userAgent);

    if (isBot) {
      await BlockedIP.updateOne({ ip }, { $set: { reason: "Bot user-agent" } }, { upsert: true });
      return res.status(403).json({ error: "Access denied: Bots not allowed" });
    }

    // 4. GeoIP lookup
    const geo = geoip.lookup(ip);
    const country = geo?.country || "Unknown";

    // 5. ASN-based datacenter blocking
    const asn = await getASN(ip);
    if (asn && BLOCKED_ASNS.includes(asn)) {
      await BlockedIP.updateOne({ ip }, { $set: { reason: `Datacenter ASN: ${asn}` } }, { upsert: true });
      return res.status(403).json({ error: "Access denied: Datacenter IP" });
    }

    // 6. ISP-based blocking
    let isp = "";
    let ispBlocked = false;
    try {
      const ispRes = await fetch(`http://ip-api.com/json/${ip}`);
      const ispData = await ispRes.json();
      isp = (ispData.as || ispData.org || "").toLowerCase();

      const isWhitelisted = WHITELIST_ISPS.some(w => isp.includes(w.toLowerCase()));
      if (!isWhitelisted) {
        const matchISP = BANNED_ISPS.some(b => isp.includes(b.toLowerCase()));
        const matchKeyword = bannedKeywords.some(k => isp.includes(k));
        if (matchISP || matchKeyword) ispBlocked = true;
      }

      if (ispBlocked) {
        await BlockedIP.updateOne({ ip }, { $set: { reason: `Blocked ISP: ${isp}` } }, { upsert: true });
        return res.status(403).json({ error: "Access denied: Hosting/Proxy ISP detected" });
      }
    } catch (err) {
      console.error("ISP check failed:", err.message);
    }

    // 7. VPN / proxy detection
    let isVPN = false;
    try {
      if (process.env.VPN_API_KEY) {
        const vpnRes = await fetch(`https://vpnapi.io/api/${ip}?key=${process.env.VPN_API_KEY}`);
        const vpnData = await vpnRes.json();
        isVPN = vpnData.security?.vpn || vpnData.security?.proxy || vpnData.security?.tor || false;
      }

      if (!isVPN && process.env.IPQUALITY_KEY) {
        const iqRes = await fetch(`https://ipqualityscore.com/api/json/ip/${process.env.IPQUALITY_KEY}/${ip}?strictness=1`);
        const iqData = await iqRes.json();
        isVPN = iqData.vpn || iqData.proxy || iqData.tor || iqData.active_vpn || false;
      }
    } catch (err) {
      console.error("VPN check failed:", err.message);
    }

    if (isVPN || isProxyUA) {
      const reason = isVPN ? "VPN/Proxy detected" : "Suspicious user-agent";
      await BlockedIP.updateOne({ ip }, { $set: { reason } }, { upsert: true });
      ipCache.set(ip, { blocked: true, timestamp: Date.now(), reason });
      return res.status(403).json({ error: `Access denied: ${reason}` });
    }

    // ============ HUMAN CONFIRMED ============

    const visitor = new Visitor({
      ip,
      userAgent,
      path,
      isBot: false,
      country,
      tlsVersion: null,
      isMobile: /mobile|android|iphone|ipad/i.test(userAgent),
    });
    await visitor.save();

    ipCache.set(ip, { blocked: false, timestamp: Date.now() });

    res.cookie("human_verified", crypto.randomBytes(32).toString("hex"), {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 3600000,
    });

    res.status(200).json({ verified: true, country });

  } catch (err) {
    console.error("Track route error:", err);
    res.status(500).json({ error: "Internal error" });
  }
});

// Cleanup stale behavior records every hour
setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of requestTracker.entries()) {
    if (now - record.lastClean > 3600000) requestTracker.delete(ip);
  }
}, 3600000);

module.exports = router;
