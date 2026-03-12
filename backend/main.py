import hashlib
import hmac
import os
import random
import re
import smtplib
import ssl
from pathlib import Path
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any, Dict, List, Optional

import bcrypt
import httpx
from dotenv import load_dotenv
from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr, Field
from supabase import Client, create_client

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))


def parse_origins(value: str) -> List[str]:
    return [origin.strip() for origin in value.split(",") if origin.strip()]


def parse_bool(value: Optional[str], default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}

app = FastAPI(title="Secure Password Vault API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=parse_origins(
        os.getenv("CORS_ORIGINS", "http://127.0.0.1:5500,http://localhost:5500")
    ),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY", "")
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-in-production")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))
OTP_EXPIRE_MINUTES = int(os.getenv("OTP_EXPIRE_MINUTES", "10"))
LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", "900"))
MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
CAPTCHA_BYPASS_TOKEN = os.getenv("CAPTCHA_BYPASS_TOKEN", "demo-captcha-pass")
DEVELOPMENT_MODE = os.getenv("DEVELOPMENT_MODE", "true").lower() == "true"
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
IS_PRODUCTION = ENVIRONMENT == "production" or not DEVELOPMENT_MODE
TURNSTILE_SITE_KEY = os.getenv("TURNSTILE_SITE_KEY", "").strip()
TURNSTILE_SECRET_KEY = os.getenv("TURNSTILE_SECRET_KEY", "").strip()
TURNSTILE_VERIFY_URL = os.getenv(
    "TURNSTILE_VERIFY_URL",
    "https://challenges.cloudflare.com/turnstile/v0/siteverify",
).strip()
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "").strip()
SMTP_USE_TLS = parse_bool(os.getenv("SMTP_USE_TLS"), True)
SMTP_USE_SSL = parse_bool(os.getenv("SMTP_USE_SSL"), False)
BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
AUTH_COOKIE_NAME = os.getenv("AUTH_COOKIE_NAME", "spv_access_token")
COOKIE_DOMAIN = os.getenv("COOKIE_DOMAIN") or None
COOKIE_SECURE = parse_bool(os.getenv("COOKIE_SECURE"), IS_PRODUCTION)
COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "lax").lower()
BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_DIR.parent
FRONTEND_DIR = Path(os.getenv("FRONTEND_DIR", str(PROJECT_ROOT / "frontend"))).resolve()

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be configured.")

if IS_PRODUCTION:
    if JWT_SECRET == "change-me-in-production":
        raise RuntimeError("JWT_SECRET must be changed before running in production.")
    if COOKIE_SAMESITE == "none" and not COOKIE_SECURE:
        raise RuntimeError("COOKIE_SECURE must be true when COOKIE_SAMESITE is 'none'.")
    if not TURNSTILE_SECRET_KEY or not TURNSTILE_SITE_KEY:
        raise RuntimeError("TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY must be configured in production.")
    if not SMTP_HOST or not SMTP_FROM_EMAIL:
        raise RuntimeError("SMTP_HOST and SMTP_FROM_EMAIL must be configured in production.")

if COOKIE_SAMESITE not in {"lax", "strict", "none"}:
    raise RuntimeError("COOKIE_SAMESITE must be one of: lax, strict, none.")

if SMTP_USE_SSL and SMTP_USE_TLS:
    raise RuntimeError("Use only one of SMTP_USE_TLS or SMTP_USE_SSL.")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
login_attempts: Dict[str, List[datetime]] = {}


class EncryptedBlob(BaseModel):
    version: int = Field(default=1, ge=1)
    algorithm: str = Field(min_length=3, max_length=32)
    salt: str = Field(min_length=16, max_length=512)
    iv: str = Field(min_length=12, max_length=128)
    ciphertext: str = Field(min_length=24, max_length=16384)


class SignupRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    captcha_token: Optional[str] = None


class LoginRequest(SignupRequest):
    pass


class ForgotPasswordRequest(BaseModel):
    email: EmailStr
    captcha_token: Optional[str] = None


class VerifyOtpRequest(BaseModel):
    email: EmailStr
    otp: str = Field(min_length=6, max_length=6)


class ResetPasswordRequest(BaseModel):
    reset_token: str
    new_password: str = Field(min_length=8)


class MasterKeyVerifier(BaseModel):
    version: int = Field(default=1, ge=1)
    salt: str = Field(min_length=16, max_length=512)
    iterations: int = Field(default=250000, ge=100000, le=1000000)
    hash: str = Field(min_length=24, max_length=512)


class MasterKeySetupRequest(BaseModel):
    verifier: MasterKeyVerifier


class VaultPayload(BaseModel):
    encrypted_data: EncryptedBlob


class VaultUpdatePayload(VaultPayload):
    id: str


class TeamCreatePayload(BaseModel):
    name: str = Field(min_length=2, max_length=120)


class TeamMemberPayload(BaseModel):
    team_id: str
    email: EmailStr
    role: str


class TeamVaultPayload(VaultPayload):
    team_id: str


class TeamVaultUpdatePayload(TeamVaultPayload):
    entry_id: str


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def model_to_dict(model: BaseModel) -> Dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


def validate_encrypted_blob(blob: EncryptedBlob) -> Dict[str, Any]:
    payload = model_to_dict(blob)
    if payload["algorithm"] != "AES-GCM":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported encryption algorithm")

    for field_name in ("salt", "iv", "ciphertext"):
        value = payload[field_name]
        if len(value) % 4 != 0 or not BASE64_PATTERN.fullmatch(value):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid encrypted payload field: {field_name}",
            )
    return payload


def validate_master_key_verifier(verifier: MasterKeyVerifier) -> Dict[str, Any]:
    payload = model_to_dict(verifier)
    for field_name in ("salt", "hash"):
        value = payload[field_name]
        if len(value) % 4 != 0 or not BASE64_PATTERN.fullmatch(value):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid master key verifier field: {field_name}",
            )
    return payload


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def create_token(subject: str, token_type: str, expires_minutes: int) -> str:
    now = utcnow()
    payload = {
        "sub": subject,
        "type": token_type,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def set_auth_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=AUTH_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        max_age=JWT_EXPIRE_MINUTES * 60,
        expires=JWT_EXPIRE_MINUTES * 60,
        path="/",
        domain=COOKIE_DOMAIN,
    )


def clear_auth_cookie(response: Response) -> None:
    response.delete_cookie(
        key=AUTH_COOKIE_NAME,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        path="/",
        domain=COOKIE_DOMAIN,
    )


def decode_token(token: str, expected_type: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc

    if payload.get("type") != expected_type:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
    return payload


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def captcha_provider_enabled() -> bool:
    return bool(TURNSTILE_SECRET_KEY and TURNSTILE_SITE_KEY)


def smtp_enabled() -> bool:
    return bool(SMTP_HOST and SMTP_FROM_EMAIL)


def verify_turnstile_token(captcha_token: str, request: Request) -> None:
    try:
        response = httpx.post(
            TURNSTILE_VERIFY_URL,
            data={
                "secret": TURNSTILE_SECRET_KEY,
                "response": captcha_token,
                "remoteip": get_client_ip(request),
            },
            timeout=10.0,
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Captcha verification service is unavailable.",
        ) from exc

    payload = response.json()
    if not payload.get("success"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Captcha verification failed")


def ensure_captcha(captcha_token: Optional[str], request: Request) -> None:
    if captcha_provider_enabled():
        if not captcha_token:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Captcha verification is required")
        verify_turnstile_token(captcha_token, request)
        return

    if DEVELOPMENT_MODE and captcha_token == CAPTCHA_BYPASS_TOKEN:
        return

    if IS_PRODUCTION:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Captcha provider is not configured.",
        )

    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Captcha verification failed")


def ensure_login_rate_limit(email: str, request: Request) -> None:
    if DEVELOPMENT_MODE:
        return

    key = f"{get_client_ip(request)}:{email.lower()}"
    now = utcnow()
    attempts = [item for item in login_attempts.get(key, []) if (now - item).total_seconds() < LOGIN_WINDOW_SECONDS]
    login_attempts[key] = attempts
    if len(attempts) >= MAX_LOGIN_ATTEMPTS:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many login attempts")


def record_login_attempt(email: str, request: Request) -> None:
    key = f"{get_client_ip(request)}:{email.lower()}"
    login_attempts.setdefault(key, []).append(utcnow())


def clear_login_attempts(email: str, request: Request) -> None:
    key = f"{get_client_ip(request)}:{email.lower()}"
    login_attempts.pop(key, None)


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    response = supabase.table("users").select("*").eq("email", email.lower()).limit(1).execute()
    return response.data[0] if response.data else None


def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    response = supabase.table("users").select("*").eq("id", user_id).limit(1).execute()
    return response.data[0] if response.data else None


def serialize_user(user: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": user["id"], "email": user["email"], "created_at": user["created_at"]}


def get_master_key_record(user_id: str) -> Optional[Dict[str, Any]]:
    response = supabase.table("user_master_keys").select("*").eq("user_id", user_id).limit(1).execute()
    return response.data[0] if response.data else None


def hash_otp(otp: str) -> str:
    return hashlib.sha256(otp.encode("utf-8")).hexdigest()


def make_otp() -> str:
    return f"{random.randint(0, 999999):06d}"


def send_otp_email(email: str, otp: str) -> None:
    if not smtp_enabled():
        if DEVELOPMENT_MODE:
            return
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="SMTP is not configured.")

    message = EmailMessage()
    message["Subject"] = "Secure Password Vault OTP"
    message["From"] = SMTP_FROM_EMAIL
    message["To"] = email
    message.set_content(
        "\n".join(
            [
                "Your Secure Password Vault password reset OTP is below.",
                "",
                f"OTP: {otp}",
                "",
                f"This OTP expires in {OTP_EXPIRE_MINUTES} minutes.",
                "If you did not request this, you can ignore this email.",
            ]
        )
    )

    try:
        if SMTP_USE_SSL:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=15) as server:
                if SMTP_USERNAME:
                    server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(message)
            return

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            if SMTP_USE_TLS:
                context = ssl.create_default_context()
                server.starttls(context=context)
            if SMTP_USERNAME:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OTP email delivery failed.",
        ) from exc


def get_current_user(
    authorization: str = Header(default=""),
    auth_cookie: Optional[str] = Cookie(default=None, alias=AUTH_COOKIE_NAME),
) -> Dict[str, Any]:
    token = ""
    if authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1]
    elif auth_cookie:
        token = auth_cookie

    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    payload = decode_token(token, "access")
    user = get_user_by_id(payload["sub"])
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


def get_team_membership(team_id: str, user_id: str) -> Optional[Dict[str, Any]]:
    response = (
        supabase.table("team_members")
        .select("*")
        .eq("team_id", team_id)
        .eq("user_id", user_id)
        .limit(1)
        .execute()
    )
    return response.data[0] if response.data else None


def require_team_role(team_id: str, user_id: str, allowed_roles: List[str]) -> Dict[str, Any]:
    membership = get_team_membership(team_id, user_id)
    if not membership:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You are not a team member")
    if membership["role"] not in allowed_roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient team permissions")
    return membership


@app.middleware("http")
async def add_security_headers(request: Request, call_next) -> Response:
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "accelerometer=(), camera=(), geolocation=(), microphone=(), usb=()"
    if request.method == "GET" and (
        request.url.path == "/"
        or request.url.path.endswith((".html", ".js", ".css"))
    ):
        response.headers["Cache-Control"] = "no-store, max-age=0"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.exception_handler(httpx.HTTPError)
async def handle_httpx_error(request: Request, exc: httpx.HTTPError) -> JSONResponse:
    detail = "Unable to reach the Supabase backend."
    if DEVELOPMENT_MODE:
        detail = f"Supabase request failed: {exc}"
    return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"detail": detail})


@app.exception_handler(Exception)
async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    detail = "Internal server error"
    if DEVELOPMENT_MODE:
        detail = str(exc) or exc.__class__.__name__
    return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"detail": detail})


@app.get("/")
def home(request: Request):
    accepts_html = "text/html" in request.headers.get("accept", "")
    index_file = FRONTEND_DIR / "index.html"
    if accepts_html and index_file.exists():
        return FileResponse(index_file)
    return {"message": "Secure Password Vault backend is running"}


@app.get("/healthz")
def healthz() -> Dict[str, Any]:
    return {"status": "ok", "environment": ENVIRONMENT, "development_mode": DEVELOPMENT_MODE}


@app.get("/public-config")
def public_config() -> Dict[str, Any]:
    return {
        "captcha": {
            "provider": "turnstile" if captcha_provider_enabled() else "demo",
            "site_key": TURNSTILE_SITE_KEY if captcha_provider_enabled() else "",
        },
        "development_mode": DEVELOPMENT_MODE,
    }


@app.get("/me")
def get_me(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    return {"user": serialize_user(current_user)}


@app.get("/master-key")
def get_master_key(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    record = get_master_key_record(current_user["id"])
    return {
        "configured": bool(record),
        "verifier": record["verifier"] if record else None,
    }


@app.post("/master-key")
def create_master_key(
    payload: MasterKeySetupRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    existing = get_master_key_record(current_user["id"])
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Master key already configured")

    verifier = validate_master_key_verifier(payload.verifier)
    inserted = (
        supabase.table("user_master_keys")
        .insert({"user_id": current_user["id"], "verifier": verifier})
        .execute()
    )
    return {"message": "Master key configured", "profile": inserted.data[0] if inserted.data else None}


@app.put("/master-key")
def update_master_key(
    payload: MasterKeySetupRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    existing = get_master_key_record(current_user["id"])
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Master key is not configured")

    verifier = validate_master_key_verifier(payload.verifier)
    updated = (
        supabase.table("user_master_keys")
        .update({"verifier": verifier})
        .eq("user_id", current_user["id"])
        .execute()
    )
    return {"message": "Master key updated", "profile": updated.data[0] if updated.data else None}


@app.post("/signup")
def signup(payload: SignupRequest, request: Request) -> Dict[str, Any]:
    ensure_captcha(payload.captcha_token, request)
    existing_user = get_user_by_email(payload.email)
    if existing_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    inserted = (
        supabase.table("users")
        .insert(
            {
                "email": payload.email.lower(),
                "password_hash": hash_password(payload.password),
            }
        )
        .execute()
    )
    return {"message": "Account created", "user": serialize_user(inserted.data[0]) if inserted.data else None}


@app.post("/login")
def login(payload: LoginRequest, request: Request, response: Response) -> Dict[str, Any]:
    ensure_captcha(payload.captcha_token, request)
    ensure_login_rate_limit(payload.email, request)

    user = get_user_by_email(payload.email)
    if not user or not verify_password(payload.password, user["password_hash"]):
        record_login_attempt(payload.email, request)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    clear_login_attempts(payload.email, request)
    access_token = create_token(user["id"], "access", JWT_EXPIRE_MINUTES)
    set_auth_cookie(response, access_token)
    return {
        "token_type": "bearer",
        "user": serialize_user(user),
    }


@app.post("/logout")
def logout(response: Response) -> Dict[str, str]:
    clear_auth_cookie(response)
    return {"message": "Logged out"}


@app.post("/forgot-password")
def forgot_password(payload: ForgotPasswordRequest, request: Request) -> Dict[str, Any]:
    ensure_captcha(payload.captcha_token, request)
    user = get_user_by_email(payload.email)
    if not user:
        return {"message": "If that account exists, an OTP has been sent to the email address."}

    otp = make_otp()
    expires_at = utcnow() + timedelta(minutes=OTP_EXPIRE_MINUTES)
    inserted = supabase.table("password_reset_otps").insert(
        {
            "user_id": user["id"],
            "otp_hash": hash_otp(otp),
            "expires_at": expires_at.isoformat(),
        }
    ).execute()
    try:
        send_otp_email(user["email"], otp)
    except HTTPException:
        if inserted.data:
            supabase.table("password_reset_otps").delete().eq("id", inserted.data[0]["id"]).execute()
        raise

    response: Dict[str, Any] = {"message": "If that account exists, an OTP has been sent to the email address."}
    if DEVELOPMENT_MODE:
        response["development_otp"] = otp
    return response


@app.post("/verify-otp")
def verify_otp(payload: VerifyOtpRequest) -> Dict[str, str]:
    user = get_user_by_email(payload.email)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    response = (
        supabase.table("password_reset_otps")
        .select("*")
        .eq("user_id", user["id"])
        .eq("used", False)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    otp_row = response.data[0] if response.data else None
    if not otp_row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OTP not found")

    if datetime.fromisoformat(otp_row["expires_at"].replace("Z", "+00:00")) < utcnow():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP expired")

    if not hmac.compare_digest(otp_row["otp_hash"], hash_otp(payload.otp)):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OTP")

    supabase.table("password_reset_otps").update({"used": True}).eq("id", otp_row["id"]).execute()
    return {"reset_token": create_token(user["id"], "password_reset", OTP_EXPIRE_MINUTES)}


@app.post("/reset-password")
def reset_password(payload: ResetPasswordRequest) -> Dict[str, str]:
    token_payload = decode_token(payload.reset_token, "password_reset")
    user_id = token_payload["sub"]
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    supabase.table("users").update({"password_hash": hash_password(payload.new_password)}).eq("id", user_id).execute()
    return {"message": "Password updated"}


@app.get("/vault")
def get_vault(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    response = (
        supabase.table("vault")
        .select("*")
        .eq("user_id", current_user["id"])
        .order("created_at", desc=True)
        .execute()
    )
    return {"items": response.data}


@app.post("/vault/add")
def add_vault(payload: VaultPayload, current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    encrypted_data = validate_encrypted_blob(payload.encrypted_data)
    inserted = (
        supabase.table("vault")
        .insert({"user_id": current_user["id"], "encrypted_data": encrypted_data})
        .execute()
    )
    return {"message": "Vault item added", "item": inserted.data[0] if inserted.data else None}


@app.put("/vault/update")
def update_vault(payload: VaultUpdatePayload, current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    encrypted_data = validate_encrypted_blob(payload.encrypted_data)
    existing = (
        supabase.table("vault")
        .select("*")
        .eq("id", payload.id)
        .eq("user_id", current_user["id"])
        .limit(1)
        .execute()
    )
    if not existing.data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vault item not found")

    updated = (
        supabase.table("vault")
        .update({"encrypted_data": encrypted_data})
        .eq("id", payload.id)
        .eq("user_id", current_user["id"])
        .execute()
    )
    return {"message": "Vault item updated", "item": updated.data[0] if updated.data else None}


@app.delete("/vault/delete")
def delete_vault(
    id: str = Query(...),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, str]:
    existing = (
        supabase.table("vault")
        .select("id")
        .eq("id", id)
        .eq("user_id", current_user["id"])
        .limit(1)
        .execute()
    )
    if not existing.data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vault item not found")

    supabase.table("vault").delete().eq("id", id).eq("user_id", current_user["id"]).execute()
    return {"message": "Vault item deleted"}


@app.post("/team/create")
def create_team(payload: TeamCreatePayload, current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    created_team = (
        supabase.table("teams")
        .insert({"name": payload.name, "created_by": current_user["id"]})
        .execute()
    )
    team = created_team.data[0]
    supabase.table("team_members").insert(
        {"team_id": team["id"], "user_id": current_user["id"], "role": "admin"}
    ).execute()
    return {"message": "Team created", "team": team}


@app.post("/team/add-member")
def add_member(payload: TeamMemberPayload, current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, str]:
    role = payload.role.lower()
    if role not in {"admin", "member", "viewer"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role")

    require_team_role(payload.team_id, current_user["id"], ["admin"])
    member_user = get_user_by_email(payload.email)
    if not member_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target user not found")

    existing = get_team_membership(payload.team_id, member_user["id"])
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User is already a team member")

    supabase.table("team_members").insert(
        {"team_id": payload.team_id, "user_id": member_user["id"], "role": role}
    ).execute()
    return {"message": "Member added"}


@app.get("/team/vault")
def get_team_vault(team_id: str = Query(...), current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    membership = require_team_role(team_id, current_user["id"], ["admin", "member", "viewer"])
    response = (
        supabase.table("team_vault")
        .select("*")
        .eq("team_id", team_id)
        .order("created_at", desc=True)
        .execute()
    )
    return {"role": membership["role"], "items": response.data}


@app.post("/team/vault/add")
def add_team_vault(payload: TeamVaultPayload, current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    require_team_role(payload.team_id, current_user["id"], ["admin"])
    encrypted_data = validate_encrypted_blob(payload.encrypted_data)
    inserted = (
        supabase.table("team_vault")
        .insert(
            {
                "team_id": payload.team_id,
                "created_by": current_user["id"],
                "encrypted_data": encrypted_data,
            }
        )
        .execute()
    )
    return {"message": "Team vault item added", "item": inserted.data[0] if inserted.data else None}


@app.put("/team/vault/update")
def update_team_vault(
    payload: TeamVaultUpdatePayload,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    require_team_role(payload.team_id, current_user["id"], ["admin"])
    encrypted_data = validate_encrypted_blob(payload.encrypted_data)
    updated = (
        supabase.table("team_vault")
        .update({"encrypted_data": encrypted_data})
        .eq("id", payload.entry_id)
        .eq("team_id", payload.team_id)
        .execute()
    )
    if not updated.data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team vault item not found")
    return {"message": "Team vault item updated", "item": updated.data[0]}


@app.delete("/team/vault/delete")
def delete_team_vault(
    team_id: str = Query(...),
    entry_id: str = Query(...),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, str]:
    require_team_role(team_id, current_user["id"], ["admin"])
    existing = (
        supabase.table("team_vault")
        .select("id")
        .eq("id", entry_id)
        .eq("team_id", team_id)
        .limit(1)
        .execute()
    )
    if not existing.data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team vault item not found")
    supabase.table("team_vault").delete().eq("id", entry_id).eq("team_id", team_id).execute()
    return {"message": "Team vault item deleted"}


if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
