from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from urllib.parse import urlparse

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import HTTPException, Request, status
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .models import AgentNonce, Node, Role, User


password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def get_current_user(request: Request, db: Session) -> User | None:
    username = request.session.get("username")
    if not username:
        return None
    return db.scalar(select(User).where(User.username == username, User.enabled.is_(True)))


def require_user(request: Request, db: Session) -> User:
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"})
    return user


def require_admin(request: Request, db: Session) -> User:
    user = require_user(request, db)
    if user.role != Role.admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator role required")
    return user


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf"] = token
    return token


def verify_csrf(request: Request, token: str) -> None:
    expected = request.session.get("csrf")
    if not expected or not hmac.compare_digest(expected, token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token")


def body_sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def canonical_agent_message(method: str, path: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    return f"{method.upper()}\n{path}\n{timestamp}\n{nonce}\n{body_sha256(body)}".encode("utf-8")


def verify_agent_request(request: Request, body: bytes, db: Session, max_skew_seconds: int = 300) -> Node:
    node_id = request.headers.get("X-Node-ID", "")
    timestamp = request.headers.get("X-Timestamp", "")
    nonce = request.headers.get("X-Nonce", "")
    signature = request.headers.get("X-Signature", "")
    if not all((node_id, timestamp, nonce, signature)):
        raise HTTPException(status_code=401, detail="Missing agent authentication headers")

    try:
        ts = int(timestamp)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid timestamp") from exc

    if abs(int(time.time()) - ts) > max_skew_seconds:
        raise HTTPException(status_code=401, detail="Agent timestamp outside allowed window")

    node = db.get(Node, node_id)
    if not node or not node.enabled:
        raise HTTPException(status_code=401, detail="Unknown or disabled node")

    expected = hmac.new(
        node.shared_secret.encode("utf-8"),
        canonical_agent_message(request.method, request.url.path, timestamp, nonce, body),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, signature.lower()):
        raise HTTPException(status_code=401, detail="Invalid agent signature")

    if db.scalar(select(AgentNonce.id).where(AgentNonce.node_id == node_id, AgentNonce.nonce == nonce)):
        raise HTTPException(status_code=401, detail="Replayed agent request")
    db.execute(delete(AgentNonce).where(AgentNonce.seen_at < datetime.now(timezone.utc) - timedelta(days=1)))
    db.add(AgentNonce(node_id=node_id, nonce=nonce))
    return node


def normalize_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if domain.startswith("@"):
        domain = domain[1:]
    if not domain or len(domain) > 253 or ".." in domain:
        raise ValueError("Invalid domain")
    labels = domain.split(".")
    if len(labels) < 2:
        raise ValueError("Domain must contain a dot")
    for label in labels:
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            raise ValueError("Invalid domain label")
        if not all(ch.isalnum() or ch == "-" for ch in label):
            raise ValueError("Invalid domain characters")
    return domain


def normalize_ip(value: str) -> str:
    return str(ip_address(value.strip()))
