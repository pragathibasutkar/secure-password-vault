# Secure Password Vault Setup

## Project structure

- `backend/main.py`
  FastAPI API for auth, OTP reset, JWT sessions, personal vault entries, and team vault sharing.
- `backend/requirements.txt`
  Python dependencies.
- `backend/.env.example`
  Environment variables required for the API.
- `Dockerfile`
  Single-container production deployment that serves the frontend and API from one origin.
- `database/schema.sql`
  Supabase PostgreSQL schema for users, vault, OTP, teams, and team vault tables.
- `frontend/index.html`
  Landing page.
- `frontend/login.html`
  Login page with password strength meter, captcha placeholder, forgot-password, OTP verify, and reset password flows.
- `frontend/signup.html`
  Signup page.
- `frontend/dashboard.html`
  Authenticated summary page.
- `frontend/vault.html`
  Personal password vault UI with local unlock, show/copy/edit/delete, and encrypted backup export/import.
- `frontend/team-vault.html`
  Team vault UI with team creation, membership, and encrypted shared entries.
- `frontend/js/*.js`
  API client, session helpers, WebCrypto encryption, and per-page logic.

## Local development

1. Copy `backend/.env.example` to `backend/.env`.
2. Fill in:
   - `SUPABASE_URL`
   - `SUPABASE_SERVICE_ROLE_KEY`
   - `JWT_SECRET`
   - `ENVIRONMENT`
   - `CORS_ORIGINS`
   - `TURNSTILE_SITE_KEY`
   - `TURNSTILE_SECRET_KEY`
   - `SMTP_HOST`
   - `SMTP_PORT`
   - `SMTP_USERNAME`
   - `SMTP_PASSWORD`
   - `SMTP_FROM_EMAIL`
   - Cookie settings if frontend and backend are deployed on different origins

   For local development use:

```env
DEVELOPMENT_MODE=true
ENVIRONMENT=development
CAPTCHA_BYPASS_TOKEN=demo-captcha-pass
TURNSTILE_SITE_KEY=
TURNSTILE_SECRET_KEY=
SMTP_HOST=
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_FROM_EMAIL=
SMTP_USE_TLS=true
SMTP_USE_SSL=false
COOKIE_SECURE=false
COOKIE_SAMESITE=lax
```

   For production use:

```env
DEVELOPMENT_MODE=false
ENVIRONMENT=production
JWT_SECRET=<long-random-secret>
TURNSTILE_SITE_KEY=<cloudflare-turnstile-site-key>
TURNSTILE_SECRET_KEY=<cloudflare-turnstile-secret-key>
SMTP_HOST=<smtp-host>
SMTP_PORT=587
SMTP_USERNAME=<smtp-username>
SMTP_PASSWORD=<smtp-password>
SMTP_FROM_EMAIL=<verified-from-address>
SMTP_USE_TLS=true
SMTP_USE_SSL=false
COOKIE_SECURE=true
COOKIE_SAMESITE=lax
```
3. Run the SQL in `database/schema.sql` inside the Supabase SQL editor.
4. Install dependencies:

```bash
cd backend
pip install -r requirements.txt
```

5. Start the API:

```bash
cd backend
uvicorn main:app --reload
```

The API listens on `http://127.0.0.1:8000` by default and serves the frontend pages from the project `frontend/` directory.

Health check:

```bash
curl http://127.0.0.1:8000/healthz
```

Then open:

- `http://127.0.0.1:8000/index.html`
- `http://127.0.0.1:8000/login.html`
- `http://127.0.0.1:8000/dashboard.html`

If your frontend is served from a different host than the API in production, set one of these before loading the app:

- Add `<meta name="api-base-url" content="https://your-api-host">` to the page HTML
- Or set `localStorage.spv_api_base_url = "https://your-api-host"`

If frontend and backend are on different origins in production, make sure:

- `CORS_ORIGINS` includes the exact frontend origin
- `COOKIE_SAMESITE=none`
- `COOKIE_SECURE=true`
- both frontend and backend are served over HTTPS

## Production deployment

Recommended: deploy as a single container so the frontend and backend share one origin.

Build locally:

```bash
docker build -t secure-password-vault .
```

Run locally with production-like settings:

```bash
docker run --rm -p 8000:8000 --env-file backend/.env secure-password-vault
```

Container runtime notes:

- Set `ENVIRONMENT=production`
- Set `DEVELOPMENT_MODE=false`
- Set real `TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET_KEY`
- Set working SMTP settings so password reset emails can be delivered
- Set `COOKIE_SECURE=true`
- If everything is served from one domain, keep `COOKIE_SAMESITE=lax`
- If frontend and backend are split across origins, use `COOKIE_SAMESITE=none`
- Make sure `CORS_ORIGINS` includes the exact frontend origin

Suggested production smoke checks:

```bash
curl https://your-domain/healthz
curl -I https://your-domain/index.html
```

## Security model

- Account passwords are used only for backend authentication and are bcrypt hashed server-side.
- Auth sessions are stored in an HTTP-only cookie instead of a frontend-readable bearer token.
- Login, signup, and forgot-password now support Cloudflare Turnstile with server-side verification.
- Vault secrets are encrypted in the browser with `PBKDF2 -> AES-GCM` before they are sent to FastAPI.
- The backend stores only encrypted vault blobs in `vault.encrypted_data` and `team_vault.encrypted_data`.
- Personal vault decryption uses a local master password entered on the vault page and kept only in `sessionStorage`.
- Team vault decryption uses a shared passphrase that teammates exchange outside the system.
- Login routes include an in-memory rate limiter and a development fallback captcha token.
- The backend validates the encrypted payload shape before writing it to the database.
- OTP reset works for account passwords only and can send OTP emails through SMTP.

## Production follow-up

- Serve both frontend and backend over HTTPS only.
- Rotate the JWT secret and Supabase service-role key outside source control.
- Add RLS policies if you later move away from a backend-only service-role model.
