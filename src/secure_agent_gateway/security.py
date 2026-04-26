import json
from datetime import datetime, timedelta

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from secure_agent_gateway.config import Settings, get_settings
from secure_agent_gateway.crypto import canonical_json, safe_verify, sha256_hex, to_utc, utcnow
from secure_agent_gateway.db import get_db
from secure_agent_gateway.models import Principal, ReplayNonce


def admin_guard(
    x_admin_token: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> None:
    if x_admin_token != settings.admin_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid admin token")


def get_active_principal(db: Session, principal_id: str) -> Principal:
    principal = db.query(Principal).filter(Principal.principal_id == principal_id).first()
    if principal is None or not principal.active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unknown or inactive principal",
        )
    return principal


async def signed_request_guard(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Principal:
    principal_id = request.headers.get("X-Principal-Id")
    timestamp = request.headers.get("X-Timestamp")
    nonce = request.headers.get("X-Nonce")
    signature = request.headers.get("X-Signature")
    if not all([principal_id, timestamp, nonce, signature]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing auth headers")

    principal = get_active_principal(db, principal_id)
    try:
        request_time = to_utc(datetime.fromisoformat(timestamp))
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid timestamp",
        ) from exc

    now = utcnow()
    if abs((now - request_time).total_seconds()) > settings.request_ttl_seconds:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Stale signed request")

    body = await request.body()
    if body and request.headers.get("content-type", "").startswith("application/json"):
        body = canonical_json(json.loads(body))
    body_hash = sha256_hex(body)
    signed_material = (
        f"{request.method}|{request.url.path}|{timestamp}|{nonce}|{body_hash}".encode()
    )
    if not safe_verify(principal.public_signing_key, signed_material, signature):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bad request signature",
        )

    existing = (
        db.query(ReplayNonce)
        .filter(
            ReplayNonce.principal_id == principal_id,
            ReplayNonce.nonce == nonce,
            ReplayNonce.purpose == "http-request",
        )
        .first()
    )
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Replay detected")

    db.add(
        ReplayNonce(
            principal_id=principal_id,
            nonce=nonce,
            purpose="http-request",
            expires_at=now + timedelta(seconds=settings.nonce_ttl_seconds),
        )
    )
    db.flush()
    return principal
