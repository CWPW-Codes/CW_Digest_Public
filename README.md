# CW Digest

This keeps your original `newsletter-digest.html` format and updates that same file directly from Gmail.

## What This Does

- Pulls newsletter emails from Gmail (Politico, Substack, Stephen Bush `Inside Politics`, plus broader newsletter discovery from `category:updates` + `category:primary`).
- Extracts best article links (but opens Gmail by default so you always land back in your inbox thread).
- Rebuilds the `const DATA = { ... }` block in `newsletter-digest.html` for the current Sat->Fri week.
- Updates the visible week label (`W/C ...`) in the sidebar.
- Writes/updates an archive so previous weeks stay available.
- Optional: generates punchy 3-line AI summaries per item.
- Filters out obvious non-news bulk mail (promo/tracking/event invite noise).
- Includes rich UI controls in the digest page:
  - whole-week search (`/` shortcut)
  - topic heat chips
  - dark mode toggle with persistence
  - sort toggle (`Newest` / `Source`)
  - refresh button (runs Gmail sync from inside the page)
  - archive selector (jump to previous weeks)
  - reading progress bar
  - spinning avatar widget (fallbacks to `CW` badge if image missing)

No separate app UI. Your HTML file remains the product.

## One-Time Setup

```bash
cd "/path/to/CW_Digest"
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp .env.example .env
```

OAuth credentials file (Desktop app JSON):

- Put it at:
  `./config/google_oauth_client.json`
- A placeholder template is included at:
  `./config/google_oauth_client.example.json`

You already have one, so this should now be set.

OpenAI key:

- Put `OPENAI_API_KEY=...` in `.env`:
  `./.env`
- The script now auto-loads this `.env` file, so you do not need to `export` each run.
- Optional `.env` overrides:
  - `CW_DIGEST_OAUTH_CLIENT_FILE` (OAuth client JSON path)
  - `CW_DIGEST_GMAIL_TOKEN_FILE` (token JSON path)
  - `GOOGLE_OAUTH_CLIENT_ID` / `GOOGLE_OAUTH_CLIENT_SECRET` (alternative to credentials file)

## Git Safety (Public Repo)

These are now ignored by default in `.gitignore`:

- `.env` and `.env.*` (except `.env.example`)
- OAuth client JSONs (`config/google_oauth_client.json`, `client_secret_*.json`)
- Local token caches (`token.json`, `gmail_token.json`, `*.token.json`)
- Generated private data (`data/archive_weeks.json`, `data/weeks/*.json`, `data/ai_summary_cache.json`)

Before your first public push:

1. Keep real secrets only in `.env` / local JSON files (never in tracked files).
2. If any real keys were ever committed in any repo history, rotate them first (OpenAI + Google OAuth).
3. Rebuild local data after clone by running refresh/sync commands.

## Run It (Recommended)

Start the local server (needed for in-page `Refresh` and archive API):

```bash
cd "/path/to/CW_Digest"
.venv/bin/python scripts/serve_digest.py
```

Then open:

```bash
open "http://127.0.0.1:8765/newsletter-digest.html"
```

From the page:

- Click `Refresh` to rerun Gmail sync (`--sync-html --source all --max-results 25`).
- Use the archive dropdown to view older weeks.

## Run a Manual Sync (CLI)

If you want to sync from terminal without clicking refresh:

```bash
cd "/path/to/CW_Digest"
.venv/bin/python scripts/fetch_gmail_digest.py --sync-html --source all --max-results 25
```

Then either open the server URL above, or open `newsletter-digest.html` directly (note: direct file-open will not support the in-page `Refresh` button).

Optional avatar image:

- Put your face image at:
  `./assets/calum-face.jpg`
- If this file is missing, the top-right spinner shows a `CW` fallback badge automatically.

## Source Explained

`--source` controls what to fetch:

- `all` (recommended): Politico + Substack + Stephen Bush + general newsletter discovery
- `politico`
- `substack`
- `stephen_bush`
- `newsletters` (broad discovery with relevance filtering)

For your use case, stick with `--source all`.

Important:
- The HTML shows only the current Sat->Fri week.
- Substack detection includes both normal `substack.com` senders and `via Everyone` senders that match Substack-style emails.
- Stephen Bush detection is keyed off `Inside Politics` subject lines (including `via Everyone` senders).

## Useful Variants

Fetch more emails per source:

```bash
.venv/bin/python scripts/fetch_gmail_digest.py --sync-html --source all --max-results 60
```

Override query for a one-off run:

```bash
.venv/bin/python scripts/fetch_gmail_digest.py --sync-html --source politico --query 'from:politico.eu newer_than:7d'
```

Use AI summaries (optional):

```bash
.venv/bin/python scripts/fetch_gmail_digest.py --sync-html --source all --max-results 25 --ai-summaries --ai-model gpt-4o-mini
```

AI summary cache (stable, no repeated calls for unchanged emails):

- Default cache file:
  `./data/ai_summary_cache.json`
- On reruns, cached summaries are reused when message content hash + model match.
- Cache is style-versioned, so a summary style upgrade refreshes once, then stays stable again.
- Override cache path if needed:

```bash
.venv/bin/python scripts/fetch_gmail_digest.py --sync-html --source all --ai-summaries --summary-cache-file "/custom/path/ai_summary_cache.json"
```

## Archive Files

- Archive index:
  `./data/archive_weeks.json`
- Per-week snapshots:
  `./data/weeks/<week_id>.json`

Each sync updates the current week snapshot and keeps prior weeks available in the archive dropdown.

## Link Behavior (Now Gmail-First)

- Card title and `Open` button always prefer `gmail_link` when present.
- If no Gmail permalink is available, the item falls back to the extracted publisher/article URL.
- Label changes to `Open in Gmail` when Gmail is the active target.

## First-Run Auth Notes

On first run, browser auth opens and token is saved at:

- `~/.config/cw-digest/gmail_token.json`

If auth/API config changed and you need a reset:

```bash
rm -f ~/.config/cw-digest/gmail_token.json
```

## Optional: Daily Automation (local)

Run daily at 08:00 with `launchd` (I can add this for you if you want), but you can also just run the sync command manually any time.

## Tests

```bash
.venv/bin/python -m pytest -q tests/test_fetch_gmail_digest.py
```
