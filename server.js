/* ==========================================================================
   PhishGuardX - BACKEND SERVER
   ==========================================================================
   Simple Node.js + Express server.

   What this file does:
   1. Serves the frontend (the HTML/CSS/JS dashboard) from the "public" folder
   2. Exposes a few API routes that the frontend calls with fetch():
        POST /api/scan/url    -> analyze a URL,   save it,   return the result
        POST /api/scan/email  -> analyze an email, save it,  return the result
        GET  /api/history     -> return all past scans (newest first)
        GET  /api/stats       -> return totals for the dashboard cards
        DELETE /api/history   -> clear all history (used by the "Clear" button)
   3. Saves every scan into a simple JSON file (data/history.json) so your
      history is still there even after you restart the server or refresh
      the page. This is the "database" for this project - no MySQL/Mongo
      setup needed, which keeps things simple.
   ========================================================================== */

const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;

/* ------------------------------------------------------------------------
   0) TERMINAL LOGGING HELPERS
   ------------------------------------------------------------------------
   These just print colored, readable lines to the terminal so you can SEE
   the backend working live while you demo the project — every request,
   every scan, and every save shows up here. This does not use any extra
   npm package; it's plain console.log with ANSI color codes.
   ------------------------------------------------------------------------ */
const color = {
  reset: '\x1b[0m', dim: '\x1b[2m', bold: '\x1b[1m',
  cyan: '\x1b[36m', green: '\x1b[32m', yellow: '\x1b[33m', red: '\x1b[31m', blue: '\x1b[34m'
};

function timestamp() {
  return new Date().toLocaleTimeString();
}

// Prints the final verdict of a scan, color-coded to match its risk level
function logVerdict(result) {
  const verdictColor =
    result.verdict === 'SAFE' ? color.green :
    result.verdict === 'SUSPICIOUS' ? color.yellow : color.red;
  console.log(`  ${verdictColor}${color.bold}→ ${result.verdict}${color.reset} ${color.dim}(risk score: ${result.riskPct}%)${color.reset}`);
}

// Logs every incoming request the moment it hits the server
app.use((req, res, next) => {
  console.log(`${color.dim}[${timestamp()}]${color.reset} ${color.blue}${req.method}${color.reset} ${req.path}`);
  next();
});

// Lets the server understand JSON sent from the frontend (fetch(...,{body: JSON...}))
app.use(express.json());

// Serves everything inside /public as the website (index.html, css, etc.)
app.use(express.static(path.join(__dirname, 'public')));

/* ------------------------------------------------------------------------
   1) VERY SIMPLE "DATABASE": a JSON file on disk
   ------------------------------------------------------------------------ */
const DATA_FILE = path.join(__dirname, 'data', 'history.json');

// Make sure the data folder + file exist before we try to use them
function ensureDataFile() {
  const dir = path.dirname(DATA_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, '[]', 'utf-8');
}

function readHistory() {
  ensureDataFile();
  const raw = fs.readFileSync(DATA_FILE, 'utf-8');
  try {
    return JSON.parse(raw);
  } catch (e) {
    return []; // if the file ever gets corrupted, just start fresh
  }
}

function saveHistory(historyArray) {
  ensureDataFile();
  fs.writeFileSync(DATA_FILE, JSON.stringify(historyArray, null, 2), 'utf-8');
}

/* ------------------------------------------------------------------------
   2) DETECTION LOGIC
   This is the same rule-based logic your frontend used to do in the
   browser - now it runs safely on the SERVER instead. This is the real
   "backend brain" of the project.
   ------------------------------------------------------------------------ */

const SUSPICIOUS_WORDS = ['login', 'verify', 'secure', 'account', 'update', 'confirm', 'signin', 'banking', 'password', 'webscr', 'ebayisapi', 'wallet', 'suspend', 'urgent', 'click', 'limited'];
const SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly'];
const RISKY_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click', '.loan'];
const KNOWN_BRANDS = ['paypal', 'google', 'microsoft', 'amazon', 'apple', 'facebook', 'instagram', 'netflix', 'bankofamerica', 'chase', 'icici', 'sbi', 'hdfc'];

// Tries a couple of common number-to-letter swaps, e.g. "paypa1" -> "paypal"
function deLeetVariants(text) {
  const v1 = text.replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e').replace(/4/g, 'a').replace(/5/g, 's');
  const v2 = text.replace(/0/g, 'o').replace(/1/g, 'i').replace(/3/g, 'e').replace(/4/g, 'a').replace(/5/g, 's');
  return [text, v1, v2];
}

// Checks if a domain name looks like a fake copy of a known brand
function findBrandMatch(domainName) {
  const original = (domainName || '').toLowerCase();
  const tokens = original.split('-').filter(Boolean);

  if (tokens.length === 1) {
    for (const variant of deLeetVariants(original)) {
      for (const brand of KNOWN_BRANDS) {
        if (variant === brand && original !== brand) return brand;
      }
    }
    return null;
  }

  for (const token of tokens) {
    for (const variant of deLeetVariants(token)) {
      for (const brand of KNOWN_BRANDS) {
        if (variant === brand) return brand;
      }
    }
  }
  return null;
}

/* --------------------------------------------------------------------
   IMPORTANT: how the scoring works (read this if you're explaining it)
   --------------------------------------------------------------------
   Every check below has a "weight" = how many risk points it adds IF
   IT FAILS. We simply ADD UP the points of every FAILED check. That
   total (capped at 100) IS the risk score. We do NOT average it
   against the checks that passed — a domain doesn't become "safe"
   just because it also happens to pass 9 other unrelated checks.

   This matters because a few signals are strong red flags on their
   own (raw IP address, a risky TLD like .tk, punycode tricks, or a
   domain that impersonates a known brand). Each of those is given a
   weight of 40+ by itself, so even if it's the ONLY thing that fails,
   the total already crosses the "phishing" line. That is what a real
   detector should do — one serious red flag is enough to be unsafe.

   Final verdict:
     riskPct < 20        -> SAFE
     20 <= riskPct < 40   -> SUSPICIOUS
     riskPct >= 40        -> PHISHING
   -------------------------------------------------------------------- */

function analyzeUrl(raw) {
  const signals = [];
  let url = (raw || '').trim();
  let hasProtocol = /^https?:\/\//i.test(url);
  let testUrl = hasProtocol ? url : 'http://' + url;

  let host = '';
  try {
    host = new URL(testUrl).hostname;
  } catch (e) {
    host = url.split('/')[0];
  }
  host = host.toLowerCase();

  // --- Strong red flags (each one alone is enough to call it PHISHING) ---
  const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
  signals.push({ ok: !isIP, weight: 42, text: 'Uses a raw IP address instead of a domain name' });

  const hasAt = url.includes('@');
  signals.push({ ok: !hasAt, weight: 42, text: '"@" symbol present in URL (redirect trick)' });

  const riskyTld = RISKY_TLDS.find(t => host.endsWith(t));
  signals.push({ ok: !riskyTld, weight: 42, text: riskyTld ? `High-risk TLD detected (${riskyTld})` : 'No high-risk TLD (.tk/.ml/.xyz etc.) detected' });

  const isPunycode = host.includes('xn--');
  signals.push({ ok: !isPunycode, weight: 42, text: 'Punycode/homograph encoding detected (fake lookalike domain)' });

  const domainParts = host.replace(/^www\./, '').split('.');
  const domainName = domainParts.length > 1 ? domainParts[domainParts.length - 2] : domainParts[0];
  const brandHit = findBrandMatch(domainName);
  signals.push({ ok: !brandHit, weight: 46, text: brandHit ? `Domain "${domainName}" closely resembles known brand "${brandHit}" (typosquat)` : 'No brand impersonation / typosquatting detected' });

  // --- Medium red flags (add up to push a URL into SUSPICIOUS/PHISHING) ---
  // Check the domain against the shortener list properly (exact match or a
  // real subdomain of it) — NOT a raw substring check. A plain .includes()
  // would wrongly match domains like "flipkart.com" against "t.co", since
  // "flipkart.com" literally contains the text "t.co" inside it!
  const hasShortener = SHORTENERS.some(s => host === s || host.endsWith('.' + s));
  signals.push({ ok: !hasShortener, weight: 22, text: 'Uses a known URL shortener service' });

  const hasKeyword = SUSPICIOUS_WORDS.some(w => url.toLowerCase().includes(w));
  signals.push({ ok: !hasKeyword, weight: 14, text: 'Contains suspicious keywords (login/verify/secure etc.)' });

  // --- Minor red flags (small nudge, rarely decide the verdict alone) ---
  // Only judge http-vs-https when the user actually typed a protocol.
  // If they just typed "example.com" with no protocol, we genuinely don't
  // know which one it uses, so we don't penalize it.
  const notHttps = hasProtocol && url.toLowerCase().startsWith('http://');
  signals.push({ ok: !notHttps, weight: 6, text: 'Uses plain HTTP instead of HTTPS' });

  const longUrl = url.length > 75;
  signals.push({ ok: !longUrl, weight: 6, text: `URL is suspiciously long (${url.length} chars)` });

  const dotCount = (host.match(/\./g) || []).length;
  signals.push({ ok: dotCount <= 3, weight: 10, text: `Excessive number of subdomains (${dotCount} dots in domain)` });

  const hyphenCount = (host.match(/-/g) || []).length;
  signals.push({ ok: hyphenCount <= 1, weight: 10, text: `Multiple hyphens in domain (${hyphenCount})` });

  return computeVerdict(signals, url, 'url');
}

function analyzeEmail(raw) {
  const signals = [];
  const email = (raw || '').trim();
  const validFormat = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  signals.push({ ok: validFormat, weight: 18, text: validFormat ? 'Email format is valid' : 'Email format itself is invalid' });

  const [local, domain] = email.split('@');
  const dom = (domain || '').toLowerCase();

  // --- Strong red flags ---
  const riskyTld = RISKY_TLDS.find(t => dom.endsWith(t));
  signals.push({ ok: !riskyTld, weight: 42, text: riskyTld ? `High-risk TLD detected (${riskyTld})` : 'No high-risk TLD detected in domain' });

  const domainName = (dom.split('.')[0] || '');
  const brandHit = findBrandMatch(domainName);
  signals.push({ ok: !brandHit, weight: 46, text: brandHit ? `Sender domain "${domainName}" appears to impersonate brand "${brandHit}"` : 'No brand impersonation detected' });

  // --- Medium red flags ---
  const hasKeyword = SUSPICIOUS_WORDS.some(w => (local || '').toLowerCase().includes(w));
  signals.push({ ok: !hasKeyword, weight: 14, text: 'Suspicious keywords found in the username part' });

  const hasDigitSub = /[0-9]/.test(dom.split('.')[0] || '');
  signals.push({ ok: !hasDigitSub, weight: 16, text: 'Number-for-letter substitution in domain name (e.g. 0 for o)' });

  // --- Minor red flags ---
  const numSubs = (dom.match(/\./g) || []).length;
  signals.push({ ok: numSubs <= 2, weight: 10, text: `Excessive subdomains/dots in domain (${numSubs})` });

  const hyphenCount = (dom.match(/-/g) || []).length;
  signals.push({ ok: hyphenCount === 0, weight: 10, text: `Hyphens present in domain (${hyphenCount})` });

  return computeVerdict(signals, email, 'email');
}

// Turns the list of pass/fail checks into one final Safe / Suspicious / Phishing answer.
// Simply ADDS UP the weight of every FAILED check (capped at 100) — see the big
// comment above for why we don't average it against the checks that passed.
function computeVerdict(signals, target, type) {
  let riskPct = 0;
  for (const s of signals) if (!s.ok) riskPct += s.weight;
  riskPct = Math.min(100, riskPct);

  let verdict, cls;
  if (riskPct < 20) {
    verdict = 'SAFE'; cls = 'safe';
  } else if (riskPct < 40) {
    verdict = 'SUSPICIOUS'; cls = 'warn';
  } else {
    verdict = 'PHISHING'; cls = 'danger';
  }

  return {
    id: Date.now() + '-' + Math.random().toString(36).slice(2, 8),
    type,
    signals,
    riskPct,
    verdict,
    cls,
    target,
    scannedAt: new Date().toISOString()
  };
}

/* ------------------------------------------------------------------------
   3) API ROUTES - this is what the frontend's fetch() calls talk to
   ------------------------------------------------------------------------ */

// Scan a URL
app.post('/api/scan/url', (req, res) => {
  const { url } = req.body;
  if (!url || !url.trim()) {
    console.log(`  ${color.red}✖ No URL provided${color.reset}`);
    return res.status(400).json({ error: 'Please provide a URL to scan.' });
  }

  console.log(`  ${color.cyan}🔍 Analyzing URL:${color.reset} ${url}`);
  const result = analyzeUrl(url);
  logVerdict(result);

  const history = readHistory();
  history.unshift(result);
  saveHistory(history);
  console.log(`  ${color.dim}💾 Saved to data/history.json (${history.length} total scans)${color.reset}`);

  res.json(result);
});

// Scan an email address
app.post('/api/scan/email', (req, res) => {
  const { email } = req.body;
  if (!email || !email.trim()) {
    console.log(`  ${color.red}✖ No email provided${color.reset}`);
    return res.status(400).json({ error: 'Please provide an email to scan.' });
  }

  console.log(`  ${color.cyan}🔍 Analyzing email:${color.reset} ${email}`);
  const result = analyzeEmail(email);
  logVerdict(result);

  const history = readHistory();
  history.unshift(result);
  saveHistory(history);
  console.log(`  ${color.dim}💾 Saved to data/history.json (${history.length} total scans)${color.reset}`);

  res.json(result);
});

// Get full scan history (newest first)
app.get('/api/history', (req, res) => {
  const history = readHistory();
  console.log(`  ${color.dim}📜 Sent history (${history.length} scans)${color.reset}`);
  res.json(history);
});

// Get dashboard stats (total / safe / phishing / average risk)
app.get('/api/stats', (req, res) => {
  const history = readHistory();
  const total = history.length;
  const safe = history.filter(h => h.verdict === 'SAFE').length;
  const phishing = history.filter(h => h.verdict === 'PHISHING').length;
  const avg = total ? Math.round(history.reduce((s, h) => s + h.riskPct, 0) / total) : 0;
  console.log(`  ${color.dim}📊 Sent stats — total:${total}, safe:${safe}, phishing:${phishing}${color.reset}`);
  res.json({ total, safe, phishing, avgRisk: avg });
});

// Clear all history
app.delete('/api/history', (req, res) => {
  saveHistory([]);
  console.log(`  ${color.yellow}🗑  History cleared${color.reset}`);
  res.json({ ok: true });
});

/* ------------------------------------------------------------------------
   4) START THE SERVER
   ------------------------------------------------------------------------ */
app.listen(PORT, () => {
  ensureDataFile();
  console.log(`\n${color.green}✅ PhishGuardX server is running!${color.reset}`);
  console.log(`   Open this in your browser: ${color.cyan}http://localhost:${PORT}${color.reset}`);
  console.log(`   ${color.dim}Every scan you do will now show up right here in this terminal.${color.reset}\n`);
});
