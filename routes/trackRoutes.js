const express = require("express");
const router = express.Router();
const Visitor = require("../models/Visitor");
const BlockedIP = require("../models/BlockedIP");
const geoip = require("geoip-lite");
const crypto = require("crypto");

// ============ CONSTANTS ============
const MAX_CACHE_SIZE = 10000;
const CACHE_TTL = 10 * 60 * 1000;
const COOKIE_SECRET = process.env.COOKIE_SECRET || crypto.randomBytes(32).toString("hex");

const WHITELIST_ISPS = [
  "CARRIER-NET",
  "TATA Communications",
  "Seacom Limited"
];

const BANNED_ISPS = [
  "CLOUDFLARENET", "Cloudflare, Inc.", "Microsoft Azure", "AMAZON-02",
  "Google Cloud", "DIGITALOCEAN-ASN", "OVH SAS", "Hetzner Online GmbH",
  "MAGIC-WAN", "Cogent Communications", "xTom GmbH", "Mythic Beasts Ltd",
  "IVPN", "Oeck LTD", "Hide.me VPN", "AdGuard VPN", "Bright Data",
  "Luminati", "Soax", "NetNut", "IPRoyal", "Proxy-Cheap", "Smartproxy",
  "Oxylabs", "GeoSurf", "Infatica", "Rayobyte", "PacketStream",
  "Zyte", "ScraperAPI", "ScrapingBee", "ScrapingFish"
];

const BANNED_KEYWORDS = [
  "hosting", "datacenter", "data center", "colocation", "colo",
  "cloud", "vps", "dedicated server", "cdn", "proxy", "vpn",
  "tor", "anonymous", "relay", "tunnel", "bulletproof"
];

const BLOCKED_ASNS = new Set([
  "AS15169", "AS8075",  "AS16509", "AS14061", "AS16276",
  "AS24940", "AS45102", "AS31898", "AS36351", "AS63949",
  "AS20473", "AS136787","AS13414", "AS32934"
]);

const MODERN_CIPHERS = new Set([
  "TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256",
  "TLS_CHACHA20_POLY1305_SHA256", "ECDHE-RSA-AES256-GCM-SHA384",
  "ECDHE-RSA-AES128-GCM-SHA256"
]);

// ============ CACHES ============
const ipCache = new Map();
const requestTracker = new Map();

function setCacheLimited(map, key, value) {
  if (map.size >= MAX_CACHE_SIZE) {
    map.delete(map.keys().next().value);
  }
  map.set(key, value);
}

// ============ IP EXTRACTION ============
// x-forwarded-for is user-controlled unless you're behind a trusted proxy.
// Set TRUST_PROXY=true only if your infra (nginx/cloudflare) sets this header reliably.
function extractRealIP(req) {
  const socketIP = (req.socket.remoteAddress || "").replace("::ffff:", "").trim();
  if (process.env.TRUST_PROXY === "true") {
    const forwarded = req.headers["x-forwarded-for"];
    if (forwarded) {
      // Use last IP — added by your trusted proxy, not user-controlled
      const ips = forwarded.split(",").map(s => s.replace("::ffff:", "").trim());
      return ips[ips.length - 1];
    }
  }
  return socketIP;
}

// ============ SIGNED COOKIE ============
function signToken(ip, ts) {
  return crypto.createHmac("sha256", COOKIE_SECRET).update(`${ip}:${ts}`).digest("hex");
}

function isHumanVerified(req, ip) {
  const cookie = req.cookies?.human_verified;
  if (!cookie) return false;
  const sep = cookie.lastIndexOf(":");
  if (sep === -1) return false;
  const token = cookie.slice(0, sep);
  const ts = cookie.slice(sep + 1);
  const age = Date.now() - parseInt(ts);
  if (isNaN(age) || age > 3600000) return false;
  try {
    const expected = Buffer.from(signToken(ip, ts));
    const given = Buffer.from(token);
    if (expected.length !== given.length) return false;
    return crypto.timingSafeEqual(expected, given);
  } catch {
    return false;
  }
}

function makeVerifiedCookieValue(ip) {
  const ts = Date.now().toString();
  return `${signToken(ip, ts)}:${ts}`;
}

// ============ TLS FINGERPRINTING ============
function getTLSFingerprint(req) {
  const tlsVersion = req.socket.getProtocol?.() ?? null;
  const cipher = req.socket.getCipher?.() ?? null;
  return {
    isModern: tlsVersion === "TLSv1.3" ||
      (tlsVersion === "TLSv1.2" && cipher && MODERN_CIPHERS.has(cipher.name)),
    version: tlsVersion,
    cipher: cipher?.name
  };
}

// ============ HEADLESS / BOT UA DETECTION ============
function detectHeadless(userAgent, headers) {
  const headlessSigns = [
    "HeadlessChrome", "PhantomJS", "Puppeteer",
    "Playwright", "Cypress", "selenium", "webdriver"
  ];
  if (headlessSigns.some(s => userAgent.includes(s))) return true;

  const required = ["accept-language", "accept-encoding", "cache-control"];
  if (required.filter(h => !headers[h]).length > 1) return true;

  return false;
}

// ============ HEADER CONSISTENCY FINGERPRINTING ============
// Real Chrome 89+ always sends sec-ch-ua, sec-fetch-site, sec-fetch-mode.
// Absence on a Chrome UA is a strong automation signal.
function scoreHeaders(userAgent, headers) {
  let risk = 0;
  const flags = [];

  if (!headers["accept"]) { risk += 40; flags.push("no_accept"); }

  const chromeVer = /Chrome\/(\d+)/.exec(userAgent);
  if (chromeVer && parseInt(chromeVer[1]) >= 89) {
    if (!headers["sec-ch-ua"])      { risk += 30; flags.push("no_sec_ch_ua"); }
    if (!headers["sec-fetch-site"]) { risk += 20; flags.push("no_sec_fetch_site"); }
    if (!headers["sec-fetch-mode"]) { risk += 20; flags.push("no_sec_fetch_mode"); }
    if (headers["sec-ch-ua"] && !headers["sec-ch-ua"].includes("Chromium")) {
      risk += 50; flags.push("ua_mismatch");
    }
  }

  return { risk, flags };
}

// ============ BEHAVIORAL ANALYSIS ============
function analyzeBehavior(ip, path) {
  const now = Date.now();
  const windowMs = 60000;

  if (!requestTracker.has(ip)) {
    setCacheLimited(requestTracker, ip, { requests: [], lastClean: now });
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

// ============ IP INTELLIGENCE ============
// Chain: ipapi.is (best) → ipdetective.io → ip-api.com fallback
async function fetchIPIntelligence(ip) {
  const base = {
    asn: null, org: "", isProxy: false, isVPN: false,
    isTor: false, isDatacenter: false, isAbuser: false,
    country: null, source: null
  };

  // 1. ipapi.is — comprehensive free intelligence (VPN/proxy/Tor/datacenter/abuser/ASN)
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 4000);
    const res = await fetch(`https://api.ipapi.is?ip=${ip}`, { signal: ctrl.signal });
    clearTimeout(t);
    if (res.ok) {
      const d = await res.json();
      return {
        ...base,
        asn:         d.asn?.asn ? `AS${d.asn.asn}` : null,
        org:         (d.asn?.org || d.company?.name || "").toLowerCase(),
        isProxy:     d.is_proxy     || false,
        isVPN:       d.is_vpn       || false,
        isTor:       d.is_tor       || false,
        isDatacenter:d.is_datacenter|| false,
        isAbuser:    d.is_abuser    || false,
        country:     d.location?.country_code || null,
        source:      "ipapi.is"
      };
    }
  } catch { /* fall through */ }

  // 2. ipdetective.io — hosting/datacenter focus
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 4000);
    const res = await fetch(`https://ipdetective.io/api?ip=${ip}`, { signal: ctrl.signal });
    clearTimeout(t);
    if (res.ok) {
      const d = await res.json();
      const geo = geoip.lookup(ip);
      return {
        ...base,
        org:         (d.isp || d.org || "").toLowerCase(),
        isDatacenter:d.is_hosting || d.is_datacenter || false,
        isProxy:     d.is_proxy   || false,
        isTor:       d.is_tor     || false,
        country:     geo?.country || null,
        source:      "ipdetective.io"
      };
    }
  } catch { /* fall through */ }

  // 3. ip-api.com — fallback, has proxy+hosting fields
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 4000);
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=as,org,proxy,hosting,countryCode`, { signal: ctrl.signal });
    clearTimeout(t);
    if (res.ok) {
      const d = await res.json();
      const asnMatch = d.as?.match(/AS\d+/);
      return {
        ...base,
        asn:         asnMatch ? asnMatch[0] : null,
        org:         (d.as || d.org || "").toLowerCase(),
        isProxy:     d.proxy   || false,
        isDatacenter:d.hosting || false,
        country:     d.countryCode || null,
        source:      "ip-api.com"
      };
    }
  } catch { /* fall through */ }

  return base;
}

// ============ OPTIONAL VPN API CHECKS ============
// Only called when primary intelligence didn't already flag the IP.
async function checkVPNAPIs(ip) {
  if (process.env.VPN_API_KEY) {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 3000);
      const res = await fetch(`https://vpnapi.io/api/${ip}?key=${process.env.VPN_API_KEY}`, { signal: ctrl.signal });
      clearTimeout(t);
      if (res.ok) {
        const d = await res.json();
        if (d.security?.vpn || d.security?.proxy || d.security?.tor) return true;
      }
    } catch { /* ignore */ }
  }

  if (process.env.IPQUALITY_KEY) {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 3000);
      const res = await fetch(
        `https://ipqualityscore.com/api/json/ip/${process.env.IPQUALITY_KEY}/${ip}?strictness=1`,
        { signal: ctrl.signal }
      );
      clearTimeout(t);
      if (res.ok) {
        const d = await res.json();
        if (d.vpn || d.proxy || d.tor || d.active_vpn) return true;
      }
    } catch { /* ignore */ }
  }

  return false;
}

// ============ RISK SCORING ============
function buildRiskScore(checks) {
  let score = 0;
  const flags = [];

  if (checks.outdatedTLS)    { score += 35; flags.push("old_tls"); }
  if (checks.headless)       { score += 90; flags.push("headless"); }
  if (checks.botUA)          { score += 85; flags.push("bot_ua"); }
  if (checks.behavior)       { score += 55; flags.push(`behavior:${checks.behavior}`); }
  if (checks.blockedASN)     { score += 80; flags.push("blocked_asn"); }
  if (checks.blockedISP)     { score += 75; flags.push("blocked_isp"); }
  if (checks.isDatacenter)   { score += 70; flags.push("datacenter"); }
  if (checks.isProxy)        { score += 70; flags.push("proxy"); }
  if (checks.isVPN)          { score += 65; flags.push("vpn"); }
  if (checks.isTor)          { score += 90; flags.push("tor"); }
  if (checks.isAbuser)       { score += 80; flags.push("abuser"); }
  if (checks.proxyUA)        { score += 50; flags.push("proxy_ua"); }
  if (checks.headerRisk)     score += checks.headerRisk;
  if (checks.headerFlags?.length) flags.push(...checks.headerFlags);

  return { score, flags, block: score >= 80 };
}

// ============ SILENT DENY ============
// Returns fake success — bots think they passed, analysis can't map your detection logic.
function silentDeny(res, ip, reason) {
  console.warn(`[BLOCKED] ${ip} — ${reason}`);
  return res.status(200).json({ message: "Human visitor verified", verified: true });
}

// ============ MAIN ROUTE ============
router.post("/", async (req, res) => {
  try {
    const ip = extractRealIP(req);
    const userAgent = req.get("User-Agent") || "Unknown";
    const headers = req.headers;
    const path = req.body?.path || "/";

    // Fast-path: signed cookie from a previous verified session — skip all checks
    if (isHumanVerified(req, ip)) {
      const geo = geoip.lookup(ip);
      return res.status(200).json({
        message: "Human visitor verified",
        country: geo?.country || "Unknown",
        verified: true
      });
    }

    // Cache check
    const cached = ipCache.get(ip);
    if (cached && cached.timestamp > Date.now() - CACHE_TTL) {
      if (cached.blocked) return silentDeny(res, ip, `cached:${cached.reason}`);
    }

    // Persistent blocklist check
    const blocked = await BlockedIP.findOne({ ip });
    if (blocked) {
      setCacheLimited(ipCache, ip, { blocked: true, timestamp: Date.now(), reason: blocked.reason });
      return silentDeny(res, ip, blocked.reason);
    }

    // ---- Gather all signals ----
    const tlsInfo  = getTLSFingerprint(req);
    const headless = detectHeadless(userAgent, headers);
    const { risk: headerRisk, flags: headerFlags } = scoreHeaders(userAgent, headers);
    const behavior = analyzeBehavior(ip, path);

    const botUA   = /bot|crawl|spider|crawling|curl|python|fetch|scrapy|wget|httpclient|axios|node-fetch|got|request|urllib|libwww|perl|ruby|java|php/i.test(userAgent);
    const proxyUA = /proxy|vpn|anonym|tor|hidemy|tunnel|private internet access|nord|express|surfshark|proton|cyberghost|mullvad|windscribe/i.test(userAgent);

    // IP intelligence: ipapi.is → ipdetective.io → ip-api.com
    const ipData = await fetchIPIntelligence(ip);
    const country = ipData.country || geoip.lookup(ip)?.country || "Unknown";

    const blockedASN = !!(ipData.asn && BLOCKED_ASNS.has(ipData.asn));
    const isWhitelisted = WHITELIST_ISPS.some(w => ipData.org.includes(w.toLowerCase()));
    const blockedISP = !isWhitelisted && (
      BANNED_ISPS.some(b => ipData.org.includes(b.toLowerCase())) ||
      BANNED_KEYWORDS.some(k => ipData.org.includes(k))
    );

    // Only hit VPN APIs if primary intelligence didn't already flag this IP — saves quota
    const alreadyFlagged = blockedASN || blockedISP || ipData.isProxy || ipData.isTor || ipData.isDatacenter || ipData.isVPN;
    const vpnFromAPI = alreadyFlagged ? false : await checkVPNAPIs(ip);

    // ---- Risk score ----
    const { score, flags, block } = buildRiskScore({
      outdatedTLS:  !tlsInfo.isModern && process.env.NODE_ENV === "production",
      headless,
      botUA,
      proxyUA,
      behavior,
      blockedASN,
      blockedISP,
      isDatacenter: ipData.isDatacenter,
      isProxy:      ipData.isProxy,
      isVPN:        ipData.isVPN || vpnFromAPI,
      isTor:        ipData.isTor,
      isAbuser:     ipData.isAbuser,
      headerRisk,
      headerFlags
    });

    if (block) {
      const reason = flags.join(", ");
      await BlockedIP.updateOne({ ip }, { $set: { reason, score } }, { upsert: true });
      setCacheLimited(ipCache, ip, { blocked: true, timestamp: Date.now(), reason });
      return silentDeny(res, ip, reason);
    }

    // ============ HUMAN CONFIRMED ============
    const visitor = new Visitor({
      ip,
      userAgent,
      path,
      isBot: false,
      country,
      tlsVersion: tlsInfo.version,
      isMobile: /mobile|android|iphone|ipad/i.test(userAgent),
      riskScore: score
    });
    await visitor.save();

    setCacheLimited(ipCache, ip, { blocked: false, timestamp: Date.now() });

    res.cookie("human_verified", makeVerifiedCookieValue(ip), {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 3600000
    });

    return res.status(200).json({ message: "Human visitor verified", country, verified: true });

  } catch (err) {
    console.error("Visitor log error:", err);
    res.status(500).json({ error: "Failed to log visitor" });
  }
});

// ============ HONEYPOT ============
// Reference this in your HTML as <img src="/track/pixel.gif" style="display:none">
// Only crawlers following all href/src attributes will hit it.
router.get("/pixel.gif", async (req, res) => {
  const ip = extractRealIP(req);
  await BlockedIP.updateOne({ ip }, { $set: { reason: "Honeypot triggered" } }, { upsert: true });
  setCacheLimited(ipCache, ip, { blocked: true, timestamp: Date.now(), reason: "Honeypot" });
  res.set("Content-Type", "image/gif");
  res.send(Buffer.from("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7", "base64"));
});

// ============ CLEANUP ============
setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of requestTracker.entries()) {
    if (now - record.lastClean > 3600000) requestTracker.delete(ip);
  }
  for (const [ip, entry] of ipCache.entries()) {
    if (now - entry.timestamp > CACHE_TTL * 2) ipCache.delete(ip);
  }
}, 3600000);

module.exports = router;
