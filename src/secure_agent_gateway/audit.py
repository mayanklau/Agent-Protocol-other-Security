import json
from typing import Any

from sqlalchemy import desc
from sqlalchemy.orm import Session

from secure_agent_gateway.crypto import canonical_json, sha256_hex, utcnow
from secure_agent_gateway.models import AuditEvent


def append_audit_event(
    db: Session,
    *,
    event_type: str,
    subject_type: str,
    subject_id: str,
    actor_id: str | None,
    payload: dict[str, Any],
) -> AuditEvent:
    previous_event = db.query(AuditEvent).order_by(desc(AuditEvent.id)).first()
    prev_hash = previous_event.event_hash if previous_event else None
    event_payload = {
        "event_type": event_type,
        "subject_type": subject_type,
        "subject_id": subject_id,
        "actor_id": actor_id,
        "payload": payload,
        "prev_hash": prev_hash,
        "created_at": utcnow(),
    }
    event_hash = sha256_hex(canonical_json(event_payload))
    event = AuditEvent(
        event_type=event_type,
        subject_type=subject_type,
        subject_id=subject_id,
        actor_id=actor_id,
        payload_json=json.dumps(payload, sort_keys=True),
        prev_hash=prev_hash,
        event_hash=event_hash,
    )
    db.add(event)
    db.flush()
    return event
