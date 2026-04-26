import base64
import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def utcnow() -> datetime:
    return datetime.now(UTC)


def to_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=_json_default,
    ).encode()


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return to_utc(value).isoformat()
    raise TypeError(f"Unsupported type for canonical JSON: {type(value)!r}")


def sha256_hex(value: bytes | str) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(raw).hexdigest()


def b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def verify_ed25519_signature(public_key_b64: str, payload: bytes, signature_b64: str) -> None:
    public_key = Ed25519PublicKey.from_public_bytes(b64decode(public_key_b64))
    public_key.verify(b64decode(signature_b64), payload)


def generate_keypair() -> tuple[str, str]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_raw = private_key.private_bytes_raw()
    public_raw = public_key.public_bytes_raw()
    return b64encode(private_raw), b64encode(public_raw)


def sign_payload(private_key_b64: str, payload: bytes) -> str:
    private_key = Ed25519PrivateKey.from_private_bytes(b64decode(private_key_b64))
    signature = private_key.sign(payload)
    return b64encode(signature)


def safe_verify(public_key_b64: str, payload: bytes, signature_b64: str) -> bool:
    try:
        verify_ed25519_signature(public_key_b64, payload, signature_b64)
        return True
    except (InvalidSignature, ValueError):
        return False
