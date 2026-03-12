# secure-password-vault

Cybersecurity hackathon project for a client-side encrypted password manager built with FastAPI, Supabase, vanilla HTML/CSS/JS, and the WebCrypto API.

## Run locally

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

Then open `http://127.0.0.1:8000/index.html`.

For local development, keep `DEVELOPMENT_MODE=true` in [backend/.env.example](c:/Users/Pragathi/OneDrive/Documents/GitHub/secure-password-vault/backend/.env.example) so the auth pages use the built-in demo CAPTCHA and expose the development OTP. For production, configure Cloudflare Turnstile and SMTP in `backend/.env`.

## Deploy

The repository now supports a single-container deployment where FastAPI serves both the API and the frontend:

```bash
docker build -t secure-password-vault .
docker run --rm -p 8000:8000 --env-file backend/.env secure-password-vault
```

See [docs/setup.md](/c:/Users/Pragathi/OneDrive/Documents/GitHub/secure-password-vault/docs/setup.md) for the full environment and production checklist.
