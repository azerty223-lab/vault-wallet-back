const express = require("express");
const router = express.Router();
const Visitor = require("../models/Visitor");
const BlockedIP = require("../models/BlockedIP");
const geoip = require("geoip-lite");
const crypto = require("crypto");

// In-memory cache to avoid repeated DB lookups for the same IP
const ipCache = new Map();

// ============ INTELLIGENT 2026 BLOCKLIST ============
const WHITELIST_ISPS = [
  "CARRIER-NET",
  "TATA Communications",
  "Seacom Limited"
];

const BANNED_ISPS = [
  "CLOUDFLARENET",
  "Cloudflare, Inc.",
  "Microsoft Azure",
  "AMAZON-02",
  "Google Cloud",
  "DIGITALOCEAN-ASN",
  "OVH SAS",
  "Hetzner Online GmbH",
  "MAGIC-WAN",
  "Cogent Communications",
  "xTom GmbH",
  "Mythic Beasts Ltd",
  "IVPN",
  "Oeck LTD",
  "Hide.me VPN",
  "AdGuard VPN",
  "Bright Data",
  "Luminati",
  "Soax",
  "NetNut",
  "IPRoyal",
  "Proxy-Cheap",
  "Smartproxy",
  "Oxylabs",
  "GeoSurf",
  "Infatica",
  "Rayobyte",
  "PacketStream",
  "Zyte",
  "ScraperAPI",
  "ScrapingBee",
  "ScrapingFish"
];

// Keywords used to detect unlisted hosting/proxy ISPs
const bannedKeywords = [
  "hosting", "datacenter", "data center", "colocation", "colo",
  "cloud", "vps", "dedicated server", "cdn", "proxy", "vpn",
  "tor", "anonymous", "relay", "tunnel", "bulletproof"
];

// ============ 1. TLS FINGERPRINTING ============
function getTLSFingerprint(req) {
  const tlsVersion = req.socket.getProtocol ? req.socket.getProtocol() : null;
  const cipher = req.socket.getCipher ? req.socket.getCipher() : null;

  const modernCiphers = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256"
  ];

  return {
    isModern: tlsVersion === "TLSv1.3" || (tlsVersion === "TLSv1.2" && cipher && modernCiphers.includes(cipher.name)),
    version: tlsVersion,
    cipher: cipher?.name
  };
}

// ============ 2. HEADLESS BROWSER DETECTION ============
function isHeadlessBrowser(userAgent, headers) {
  const headlessSigns = [
    "HeadlessChrome", "PhantomJS", "Puppeteer",
    "Playwright", "Cypress", "selenium", "webdriver"
  ];

  if (headlessSigns.some(sign => userAgent.includes(sign))) return true;

  const requiredBrowserHeaders = ["accept-language", "accept-encoding", "cache-control"];
  const missingHeaders = requiredBrowserHeaders.filter(h => !headers[h]);
  if (missingHeaders.length > 1) return true;

  return false;
}

// ============ 3. BEHAVIORAL ANALYSIS ============
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

  const requestCount = record.requests.length;
  const uniquePaths = new Set(record.requests.map(r => r.path)).size;

  if (requestCount > 30) return "RATE_LIMIT_EXCEEDED";
  if (requestCount > 10 && uniquePaths === 1) return "REPETITIVE_PATH";
  if (requestCount > 5 && now - record.requests[0]?.timestamp < 3000) return "BURST_REQUEST";

  return null;
}

// ============ 4. ASN-BASED BLOCKING ============
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
  "AS13414", // Twitter (bots)
  "AS32934"  // Facebook/Meta (bots)
];

async function getASN(ip) {
  try {
    const response = await fetch(`http://ip-api.com/json/${ip}?fields=as`);
    const data = await response.json();
    const asnMatch = data.as?.match(/AS(\d+)/);
    return asnMatch ? `AS${asnMatch[1]}` : null;
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

    // Cache check
    const cached = ipCache.get(ip);
    if (cached && cached.timestamp > Date.now() - 10 * 60 * 1000) {
      if (cached.blocked) {
        return res.status(403).json({ error: cached.reason || "Blocked (cached)" });
      }
    }

    // Persistent blocklist check
    const blocked = await BlockedIP.findOne({ ip });
    if (blocked) {
      ipCache.set(ip, { blocked: true, timestamp: Date.now(), reason: blocked.reason });
      return res.status(403).json({ error: "You are blocked." });
    }

    const userAgent = req.get("User-Agent") || "Unknown";
    const headers = req.headers;
    const path = req.body.path || "/";

    // 1. TLS Fingerprinting
    const tlsInfo = getTLSFingerprint(req);
    if (!tlsInfo.isModern && process.env.NODE_ENV === "production") {
      await BlockedIP.updateOne({ ip }, { $set: { reason: "Outdated TLS (likely bot)" } }, { upsert: true });
      return res.status(403).json({ error: "Access denied: Insecure connection" });
    }

    // 2. Headless Browser Detection
    if (isHeadlessBrowser(userAgent, headers)) {
      await BlockedIP.updateOne({ ip }, { $set: { reason: "Headless browser detected" } }, { upsert: true });
      return res.status(403).json({ error: "Access denied: Automated browser detected" });
    }

    // 3. Behavioral Analysis
    const behavior = analyzeBehavior(ip, path);
    if (behavior) {
      await BlockedIP.updateOne({ ip }, { $set: { reason: `Behavioral block: ${behavior}` } }, { upsert: true });
      return res.status(429).json({ error: "Rate limit exceeded or suspicious pattern" });
    }

    // 4. Bot User-Agent Detection
    const isBot = /bot|crawl|spider|crawling|curl|python|fetch|scrapy|wget|httpclient|axios|node-fetch|got|request|urllib|libwww|perl|ruby|java|php/i.test(userAgent);
    const isProxyUA = /proxy|vpn|anonym|tor|hidemy|tunnel|private internet access|nord|express|surfshark|proton|cyberghost|mullvad|windscribe/i.test(userAgent);

    if (isBot) {
      await BlockedIP.updateOne({ ip }, { $set: { reason: "Bot User-Agent detected" } }, { upsert: true });
      return res.status(403).json({ error: "Access denied: Bots not allowed" });
    }

    // 5. GeoIP & ISP Check
    const geo = geoip.lookup(ip);
    const country = geo?.country || "Unknown";

    const asn = await getASN(ip);
    if (asn && BLOCKED_ASNS.includes(asn)) {
      await BlockedIP.updateOne({ ip }, { $set: { reason: `Datacenter ASN: ${asn}` } }, { upsert: true });
      return res.status(403).json({ error: "Access denied: Datacenter IPs not allowed" });
    }

    let isp = "";
    let ispBlocked = false;
    try {
      const ispRes = await fetch(`http://ip-api.com/json/${ip}`);
      const ispData = await ispRes.json();
      isp = (ispData.as || ispData.org || "").toLowerCase();

      const isWhitelisted = WHITELIST_ISPS.some(wl => isp.includes(wl.toLowerCase()));
      if (!isWhitelisted) {
        const matchISP = BANNED_ISPS.some(b => isp.includes(b.toLowerCase()));
        const matchKeyword = bannedKeywords.some(k => isp.includes(k));
        if (matchISP || matchKeyword) ispBlocked = true;
      }

      if (ispBlocked) {
        const reason = `Blocked ISP: ${isp}`;
        await BlockedIP.updateOne({ ip }, { $set: { reason } }, { upsert: true });
        return res.status(403).json({ error: "Access denied: Hosting/Proxy detected" });
      }
    } catch (ispError) {
      console.error("ISP check failed:", ispError);
    }

    // 6. VPN Detection
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
        isVPN = isVPN || iqData.vpn || iqData.proxy || iqData.tor || iqData.active_vpn;
      }
    } catch (vpnError) {
      console.error("VPN check failed:", vpnError);
    }

    if (isVPN || isProxyUA) {
      const reason = isVPN ? "VPN/Proxy Detected" : "Suspicious User-Agent";
      await BlockedIP.updateOne({ ip }, { $set: { reason } }, { upsert: true });
      ipCache.set(ip, { blocked: true, timestamp: Date.now(), reason });
      return res.status(403).json({ error: `Access denied (${reason})` });
    }

    // ============ HUMAN CONFIRMED ============
    const visitor = new Visitor({
      ip,
      userAgent,
      path,
      isBot: false,
      country,
      tlsVersion: tlsInfo.version,
      isMobile: /mobile|android|iphone|ipad/i.test(userAgent)
    });

    await visitor.save();
    ipCache.set(ip, { blocked: false, timestamp: Date.now() });

    res.cookie("human_verified", crypto.randomBytes(32).toString("hex"), {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 3600000
    });

    res.status(200).json({ message: "Human visitor verified", country, verified: true });

  } catch (err) {
    console.error("Visitor log error:", err);
    res.status(500).json({ error: "Failed to log visitor" });
  }
});

// Clean up stale behavior records every hour
setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of requestTracker.entries()) {
    if (now - record.lastClean > 3600000) requestTracker.delete(ip);
  }
}, 3600000);

module.exports = router;
