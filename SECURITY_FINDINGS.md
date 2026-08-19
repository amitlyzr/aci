# ACI — Security Audit Findings

**Service:** http://localhost:8000 (`aci-server-run-231998c031f2` container)
**Repo:** `aci/` (branch trunk/merge, backend = FastAPI)
**Scope:** Public API surface only (per owner instruction — runtime env vars excluded).
**Date:** 2026-08-19 · **Method:** unauthenticated black-box probing + source review

## Executive Summary

The ACI backend exposes **unauthenticated remote code execution as root** via `/v1/tool-seeding/run-seed-script`, arbitrary file read, unauthenticated project management that returns **decrypted API keys**, and a rate limiter whose enforcement block is commented out. This is the most severe finding across all five audited services. Treat the container as fully compromised if port 8000 was ever reachable by an untrusted party.

## Findings

| # | Severity | Finding | Endpoint(s) |
|---|----------|---------|----------|
| ACI-1 | **CRITICAL** | Unauthenticated RCE as root + event-loop DoS | `POST /v1/tool-seeding/run-seed-script` |
| ACI-2 | **CRITICAL** | `/v1/projects` fully unauthenticated; returns decrypted API keys | `GET/POST/DELETE /v1/projects*` |
| ACI-3 | **HIGH** | Arbitrary file read (two channels: `app_path`, `secrets_path`) | `POST /v1/tool-seeding/upsert-app` |
| ACI-4 | **HIGH** | Unauthenticated org-scoped tool-seeding writes | `POST /v1/tool-seeding/*` |
| ACI-5 | **HIGH** | Rate limiter disabled (enforcement commented out) | all routes |
| ACI-6 | **MEDIUM** | Billing endpoints trust org-id header alone; 500 on unknown org | `GET /v1/billing/*` |
| ACI-7 | **MEDIUM** | Plaintext website credentials + full request bodies logged | interceptor, functions routes |
| ACI-8 | **LOW** | Hidden-but-public OpenAPI docs | `/v1/notforhuman-*` |
| ACI-9 | **LOW** | Committed signing/hashing secrets in tracked `.env.example` | repo hygiene |

---

### ACI-1 — Unauthenticated RCE as root (CRITICAL)

`backend/aci/server/routes/tool_seeding.py:409-448`: `run_seed_script` takes `script_path` (query param) and `args` (body list), `chmod`s the path to 0755, then `subprocess.run([script_path] + args)`. The `auth.require_user` dependency is **commented out** (line 411); the only "auth" is the `X-ACI-ORG-ID` header, which is attacker-supplied and unvalidated.

Verified exploit (no credentials, single request):

```bash
curl -s -X POST -H "Content-Type: application/json" -H "X-ACI-ORG-ID: attacker-org" \
  -d '["-c","id; hostname"]' \
  "http://localhost:8000/v1/tool-seeding/run-seed-script?script_path=/bin/sh"
# → {"success":true,"message":"Successfully ran seeding script: uid=0(root) gid=0(root) groups=0(root)\n27d396d5a82a\n",...}
```

Also confirmed: `/bin/touch /tmp/rce_final_proof` created a file in the container (since removed). Process runs as **root** inside the container.

**DoS variant:** `subprocess.run` (blocking) inside `async def` freezes the whole uvicorn event loop — a request with `script_path=/bin/sleep&args=["600"]` took **every** endpoint (incl. `/v1/health`) down until container restart. Verified live.

**Impact:** full container takeover — read secrets from process env, pivot to linked-account OAuth tokens, exfiltrate the OpenAI key, install persistence, or simply brick the service.
**Fix:** restore `Depends(auth.require_user)`; allowlist script paths; never pass user input to `subprocess`; run blocking calls via `asyncio.to_thread` with a timeout.

### ACI-2 — Unauthenticated project management returning decrypted API keys (CRITICAL)

`backend/aci/server/routes/projects.py` — every `auth.require_user` dependency is commented out (lines 31, 118, 200, …). Worst case is the read path:

- `GET /v1/projects` (lines 116-194): requires only an `X-ACI-ORG-ID` header; for every project in that org it loads each agent's API key and returns `"key": api_key.key` — the **decrypted plaintext platform API key** (line 148) — usable against `/v1/functions/*/execute` etc. Errors are swallowed and return `[]` (lines 191-194).
- `POST /v1/projects` (lines 28-113): creates a project+agent in an attacker-chosen `org_id` (from **body**) and returns the newly minted plaintext API key in `APIKeyPublic` (line 72). The only gate is quota lookup, which 404s when no subscription plan exists.
- Also unauthenticated: `DELETE /v1/projects/{id}`, `POST /v1/projects/{id}/agents`, `DELETE .../agents/{id}`.

Verified live: `GET /v1/projects` with `X-ACI-ORG-ID: attacker-org` → `200 []` (local DB simply has no projects — the code path is the proof); `POST /v1/projects` → `404 "Subscription plan not found"`. **Any deployment with seeded plans/orgs leaks/mints keys with zero credentials.**

**Impact:** anonymous harvesting of every org's API keys → full authenticated API access as any project, plus destructive deletes.
**Fix:** re-enable all commented `Depends(auth.require_user)`; derive org from the authenticated user instead of header/body; never return raw keys from list endpoints.

### ACI-3 — Arbitrary file read via JSON-parse oracle (HIGH)

`tool_seeding.py` reads attacker paths in **two** places: `app_path` (line 99) and `secrets_path` (line 115), joined to `/workdir` if relative, absolute accepted as-is. Verified live:

```
POST /v1/tool-seeding/upsert-app {"app_path":"../../etc/passwd"}
→ "Failed to upsert app from path '../../etc/passwd': Expecting value: line 1 column 1 (char 0)"
   (file EXISTS and was read; missing paths return "App file not found")

POST .../upsert-app {"app_path":"./apps/github/app.json","secrets_path":"/workdir/pyproject.toml"}
→ "...: Expecting value: line 1 column 2 (char 1)"   ← different parse position proves TOML content was read
```

Any JSON file on disk can be exfiltrated through seeded app data; non-JSON files yield an existence oracle + first-parse-error preview.
**Fix:** resolve paths against a fixed allowlisted directory; reject `..`/absolute paths; restore auth.

### ACI-4 — Unauthenticated tool-seeding writes (HIGH)

`POST /v1/tool-seeding/upsert-app`, `upsert-functions`, `seed-tool`, `run-seed-script`, and `GET available-apps` / `seeded-apps` / `seeding-status` accept any `X-ACI-ORG-ID` with no auth (commented out at `tool_seeding.py:276,327,382,411`). Verified: `available-apps` returned the full app catalog unauthenticated; `seed-tool` executed seeding logic (200) for an attacker org. Writes into arbitrary orgs follow the same path.
**Fix:** re-enable `auth.require_user` on the whole router.

### ACI-5 — Rate limiting disabled (HIGH)

`backend/aci/server/middleware/ratelimit.py:32-44`: the entire `limiter.hit()` enforcement block is **commented out** — the middleware only attaches headers. Combined with ACI-1/2/4, unauthenticated enumeration and brute force are unlimited. (Also: `TRUSTED_PROXY_HOSTS` defaults to `*` per AciAudit, so IP keys would be spoofable via `X-Forwarded-For` anyway.)
**Fix:** restore enforcement; set explicit trusted proxies.

### ACI-6 — Billing endpoints trust org-id header alone (MEDIUM)

`routes/billing.py:39-99`: `get-subscription` and `quota-usage` take `org_id` straight from `X-ACI-ORG-ID` with no user dependency — any caller can read any org's subscription/quota state. Unknown org → `500 {"error":"Internal server error"}` (unhandled exception; verified live).
**Fix:** derive org from authenticated user; handle missing-plan explicitly. (Note: `create-checkout-session`, `create-customer-portal-session`, and Stripe webhook correctly use `auth.require_user`/signature verification.)

### ACI-7 — Credentials in logs (MEDIUM)

- `middleware/interceptor.py:88` logs full request bodies (verified in container logs during testing) — includes linked-account secrets posted to auth-gated routes.
- `routes/functions.py:304-332` dumps function execution results/inputs into logs; `AGENT_SECRETS_MANAGER__GET_CREDENTIAL_FOR_DOMAIN` returns decrypted usernames+passwords, so plaintext website credentials land in logs.
**Fix:** redact secret-bearing fields; cap body logging; exclude secrets-manager results.

### ACI-8 — Hidden-but-public OpenAPI (LOW)

Docs live at `/v1/notforhuman-docs`, `/v1/notforhuman-redoc`, `/v1/notforhuman-openapi.json` (config.py:102-104). Verified 200 with full schema — obscurity only; enumerates every unauthenticated route for an attacker.
**Fix:** disable in non-local environments.

### ACI-9 — Committed secrets in tracked `.env.example` (LOW, repo hygiene)

`backend/.env.example:29,52` contain a real-looking `SERVER_SIGNING_KEY` and `COMMON_API_KEY_HASHING_SECRET` (identical values run in the live container; tracked in git). Repo access ⇒ forge session cookies and OAuth2 state JWTs against any environment that reused example values, and offline API-key hash analysis.
**Fix:** replace with placeholders, rotate real values, add CI diff against production secrets.

---

## Attack chain (demonstrated)

1. `POST /v1/tool-seeding/run-seed-script?script_path=/bin/sh` + body `["-c","id"]` → **root shell output**, zero credentials. (ACI-1)
2. Same primitive reads process env → service credentials; reads `/workdir` → source + DB config. (ACI-1/3)
3. `GET /v1/projects` with any org header → decrypted API keys for every project in that org (once orgs exist). (ACI-2)
4. No rate limits anywhere (ACI-5) — all of the above is unthrottled and unlogged-as-anomaly.

## Positive notes

- Core agent-facing routers (`apps`, `functions`, `linked-accounts`, `app-configurations`, `analytics`, `agent`, `docs`) correctly gate everything behind `Depends(deps.get_request_context)` → `validate_api_key` (DB lookup) — held up during probing.
- OAuth callback validates a `SIGNING_KEY`-signed state JWT; Svix and Stripe webhooks verify signatures properly.
- `GET /linked-accounts/{id}/credentials` returns full plaintext credentials but is correctly auth-gated; no IDOR found.
- `app_configurations` scrubs `client_secret` in responses.
- CORS is an explicit allowlist (not wildcard) — the only one of the five services that got this right.
