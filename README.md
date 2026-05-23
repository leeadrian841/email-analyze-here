# Email Threat Analysis Platform

A **fully client-side** web app for email forensic triage. Upload an `.eml` file, or
paste raw email headers / a full email, and get a structured threat report:
phishing, BEC, sextortion, and advance-fee fraud detection — with SPF/DKIM/DMARC
interpreted *in context*.

**Everything runs in the browser.** No backend, no server, no upload, no tracking.
The email you analyze never leaves your machine — which is exactly why it can be
hosted as static files on GitHub Pages.

## Why client-side?

The original design notes (`CLAUDE.md`) describe a Python/FastAPI backend with a
database and third-party enrichment APIs. GitHub Pages only serves **static files**,
so none of that can run there. This implementation moves the entire analysis pipeline
— parsing, authentication interpretation, the detection-pattern library, IOC
extraction, severity scoring, and report rendering — into vanilla JavaScript that
executes in the visitor's browser. The trade-off: no live DNS/WHOIS/VirusTotal
enrichment (those need a server or API keys). Everything else from the spec is here.

## Features

- **Three input modes** — drag-drop `.eml`, paste full raw email, or paste headers only.
- **MIME-aware parser** — unfolds headers (order + duplicates preserved), decodes
  RFC 2047 encoded-words, walks multipart bodies, decodes base64 / quoted-printable.
- **Contextual authentication** — SPF/DKIM/DMARC are never shown as a bare green tick;
  each result is explained for what it actually proves (the three-scenario model).
- **Detection-pattern library** — GCS-bucket abuse, victim-tracking URL params,
  fabricated `X-Google-Sender-Delegation`, junk-subdomain DKIM, rsa-sha1, read-receipt
  probes, Cyrillic homoglyphs, hidden HTML text, Bayesian junk tokens, reply-channel
  misdirection, self-addressed spoofing, real-person impersonation, and more.
- **Campaign correlation** — flags overlap with known reference campaigns.
- **Severity rubric** — Critical / High / Medium / Low, auto-computed, with elevation.
- **Six-section report** — Case Summary, Email Headers (flagged rows highlighted),
  Attack Techniques, IOCs, Forensic Analysis (with raw code blocks), Recommendations.
- **Exports** — Markdown, JSON, and Print → PDF, all with optional recipient redaction.
- **Hostile-input safe** — all email-derived content is HTML-escaped; raw HTML bodies
  are never injected into the page.

## Run locally

It's static — any web server works. ES modules require `http://`, not `file://`:

```bash
# Python (no install needed)
python -m http.server 8137
# then open http://localhost:8137
```

## Deploy to GitHub Pages

1. Create a repo and push these files to the **root** of the `main` branch:
   ```bash
   git init
   git add .
   git commit -m "Email Threat Analysis Platform"
   git branch -M main
   git remote add origin https://github.com/<you>/<repo>.git
   git push -u origin main
   ```
2. On GitHub: **Settings → Pages → Build and deployment**, then pick one source:
   - **GitHub Actions** (recommended) — uses the included
     [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml), which publishes
     the repo root to Pages automatically on every push to `main`.
   - **Deploy from a branch** — set **Branch = `main` / `(root)`** and skip the workflow.
3. Wait ~1 minute. Your site is live at
   `https://<you>.github.io/<repo>/`.

The included `.nojekyll` file tells Pages to serve the `assets/` folder as-is
(no Jekyll processing). No build step is required.

## Automation (CI/CD & dependency updates)

- **GitHub Actions** — [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml)
  deploys the static site to GitHub Pages on every push to `main` (and on demand via
  *Run workflow*). It's the canonical Pages action chain: `configure-pages` →
  `upload-pages-artifact` → `deploy-pages`. Requires Pages **Source = GitHub Actions**.
- **Dependabot** — [`.github/dependabot.yml`](.github/dependabot.yml) runs weekly.
  This site has no npm/pip dependencies, so the only thing with versions to track is
  the workflow itself; Dependabot watches the `github-actions` ecosystem and opens PRs
  to bump the pinned action versions (e.g. `actions/checkout`) when updates or security
  fixes ship. Add more `package-ecosystem` blocks there if you later introduce a
  package manifest.

## Project structure

```
index.html              # page shell
.nojekyll               # disable Jekyll on GitHub Pages
.gitignore              # keeps local dev config out of the repo
.github/
  workflows/deploy.yml  # GitHub Actions → deploy to Pages
  dependabot.yml        # weekly action-version update checks
assets/
  css/styles.css        # dark security-console theme + print styles
  js/
    parser.js           # RFC 822 / MIME parser
    patterns.js         # detection constants, lexicons, campaign fingerprints
    analyzer.js         # analysis engine → EmailAnalysis object
    render.js           # safe DOM rendering (escapes all email content)
    export.js           # Markdown / JSON / PDF export
    samples.js          # synthetic demo emails (safe, fictional)
    app.js              # UI wiring
```

## Limitations

- Authentication results are **read from the email's own headers** and interpreted;
  the browser cannot perform live DKIM cryptographic verification or DNS/DMARC lookups.
- No external reputation enrichment (VirusTotal / AbuseIPDB / URLScan) — those require
  a server or API keys and are out of scope for a static site.
- Detection is heuristic and educational. It complements, not replaces, professional
  incident response.

---

_Analysis is performed entirely in your browser. Uploaded content is discarded on reload._
