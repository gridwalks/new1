# AcceleraQA (Deployable Template)

Vite + React + TS SPA with Netlify Functions (TS), Netlify Identity, Netlify Blobs, and OpenAI.

## Quickstart
```bash
npm install
cp .env.example .env
# fill in your values
npm run dev
```

## Production on Netlify
- Connect repo, set Environment variables (see `.env.example`), Deploy site.
- Required for Blobs: `NETLIFY_BLOBS_SITE_ID` (API ID from Site details) + `NETLIFY_BLOBS_TOKEN` (Personal Access Token from User settings → Applications).

## Smoke Tests
```powershell
$BASE="http://localhost:8888"
irm "$BASE/.netlify/functions/ping"
irm "$BASE/.netlify/functions/health"
irm "$BASE/.netlify/functions/chat" -Method POST -ContentType "application/json" -Body (@{message="What is 21 CFR Part 11?"} | ConvertTo-Json)
```

Troubleshooting: ensure env vars are set; redeploy after any env change.
