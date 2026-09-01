# PhishGuardX — Full Stack (Node.js + Express backend)

## Folder structure
```
PhishGuardX/
  server.js          <- backend (Express server + detection logic)
  package.json
  public/
    index.html        <- frontend (dashboard UI)
  data/
    history.json       <- auto-created, stores scan history
```

## How to run it (only 2 steps)
You need [Node.js](https://nodejs.org) installed (any recent version is fine).

1. Open a terminal in the `PhishGuardX` folder and install the one dependency:
   ```
   npm install
   ```
2. Start the server:
   ```
   npm start
   ```
   You'll see:
   ```
   ✅ PhishGuardX server is running!
      Open this in your browser: http://localhost:3000
   ```
3. Open **http://localhost:3000** in your browser. That's it — same dashboard, but now every scan actually goes to your backend.

## How it works (for your explanation / viva)
1. You type a URL/email (or upload a QR image) and click **Scan now**.
2. The frontend JS (`public/index.html`) sends that value to the backend using `fetch('/api/scan/url', ...)`.
3. `server.js` receives it, runs the rule-based checks (IP address used instead of domain, `@` trick, HTTP vs HTTPS, URL length, suspicious words like "login"/"verify", risky TLDs like `.tk`/`.xyz`, known URL shorteners, punycode, and typosquat/brand-impersonation matching), and adds up a weighted risk score.
4. It decides **SAFE / SUSPICIOUS / PHISHING** based on that score, saves the result into `data/history.json`, and sends the result back as JSON.
5. The frontend takes that JSON and draws the gauge, signal list, stat cards, trend chart, and history table — it doesn't calculate anything itself anymore.
6. For QR codes: the image is still decoded in the browser (using the `jsQR` library, since reading image pixels is a browser thing), but the **decoded link is then sent to the backend** just like a normal URL scan.

## API routes (backend)
| Method | Route              | What it does                                  |
|--------|---------------------|------------------------------------------------|
| POST   | `/api/scan/url`     | Body: `{ "url": "..." }` → returns verdict     |
| POST   | `/api/scan/email`   | Body: `{ "email": "..." }` → returns verdict   |
| GET    | `/api/history`      | Returns all saved scans (newest first)         |
| GET    | `/api/stats`        | Returns totals for the dashboard cards         |
| DELETE | `/api/history`      | Clears all saved history                       |

## Notes
- This uses a simple heuristic (rule-based) engine, not real-time threat-intel feeds — same approach as your original project, just moved to the server so it's a genuine full-stack app.
- `data/history.json` is your database. If you ever want to reset everything, just delete that file (or call `DELETE /api/history`) — it'll recreate itself empty.
