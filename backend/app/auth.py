"""Session cookie auth for the web UI and bearer token for the file API."""

from __future__ import annotations

import hashlib
import hmac
import time
from collections import defaultdict, deque
from typing import Annotated, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app.config import Settings, get_settings

bearer_scheme = HTTPBearer(auto_error=False)

# Simple in-memory login throttle: IP → timestamps of recent failures
_login_failures: dict[str, deque[float]] = defaultdict(deque)
_LOGIN_WINDOW_S = 300.0
_LOGIN_MAX_FAILURES = 20


def _serializer(settings: Settings) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(settings.session_secret, salt="aestor-web-session")


def create_session_token(settings: Settings) -> str:
    return _serializer(settings).dumps({"auth": True})


def verify_session_token(token: str, settings: Settings) -> bool:
    try:
        data = _serializer(settings).loads(token, max_age=settings.session_max_age)
        return bool(data.get("auth"))
    except (BadSignature, SignatureExpired, TypeError):
        return False


def password_matches(provided: str, settings: Settings) -> bool:
    left = hashlib.sha256(provided.encode("utf-8")).digest()
    right = hashlib.sha256(settings.web_password.encode("utf-8")).digest()
    return hmac.compare_digest(left, right)


def token_matches(provided: str, expected: str) -> bool:
    """Length-safe constant-time compare via SHA-256 digests."""
    left = hashlib.sha256(provided.encode("utf-8")).digest()
    right = hashlib.sha256(expected.encode("utf-8")).digest()
    return hmac.compare_digest(left, right)


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def assert_login_allowed(request: Request) -> None:
    ip = client_ip(request)
    now = time.time()
    q = _login_failures[ip]
    while q and now - q[0] > _LOGIN_WINDOW_S:
        q.popleft()
    if len(q) >= _LOGIN_MAX_FAILURES:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts",
        )


def record_login_failure(request: Request) -> None:
    _login_failures[client_ip(request)].append(time.time())


def clear_login_failures(request: Request) -> None:
    _login_failures.pop(client_ip(request), None)


def require_web_session(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> None:
    token: Optional[str] = request.cookies.get(settings.session_cookie_name)
    if not token or not verify_session_token(token, settings):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")


def require_api_bearer(
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Depends(bearer_scheme)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> None:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not token_matches(credentials.credentials, settings.api_bearer_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def is_authenticated_request(request: Request, settings: Settings) -> bool:
    """True if either a valid web session cookie or bearer token is present."""
    cookie = request.cookies.get(settings.session_cookie_name)
    if cookie and verify_session_token(cookie, settings):
        return True
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if token_matches(token, settings.api_bearer_token):
            return True
    return False
