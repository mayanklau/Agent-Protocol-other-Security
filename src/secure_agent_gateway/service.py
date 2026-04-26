import json
from datetime import timedelta

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from secure_agent_gateway.audit import append_audit_event
from secure_agent_gateway.config import Settings
from secure_agent_gateway.crypto import canonical_json, safe_verify, sha256_hex, to_utc, utcnow
from secure_agent_gateway.models import (
    ActionApproval,
    ActionRequest,
    MessageEnvelope,
    Principal,
    ReplayNonce,
)
from secure_agent_gateway.policy import require_scope, required_approvals_for_action, scope_allows
from secure_agent_gateway.schemas import (
    ActionApprovalIn,
    ActionExecutionIn,
    ActionRequestIn,
    MessageEnvelopeAck,
    MessageEnvelopeIn,
    PrincipalRegistration,
)


def register_principal(db: Session, payload: PrincipalRegistration) -> Principal:
    existing = db.query(Principal).filter(Principal.principal_id == payload.principal_id).first()
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Principal already exists")
    principal = Principal(
        principal_id=payload.principal_id,
        kind=payload.kind,
        display_name=payload.display_name,
        public_signing_key=payload.public_signing_key,
        public_encryption_key=payload.public_encryption_key,
        scopes_json=json.dumps(payload.scopes, sort_keys=True),
        min_approvals=payload.min_approvals,
    )
    db.add(principal)
    db.flush()
    append_audit_event(
        db,
        event_type="principal.registered",
        subject_type="principal",
        subject_id=principal.principal_id,
        actor_id=None,
        payload={"kind": principal.kind, "scopes": payload.scopes},
    )
    return principal


def _validate_temporal_window(issued_at, expires_at, settings: Settings) -> None:
    now = utcnow()
    issued_at = to_utc(issued_at)
    expires_at = to_utc(expires_at)
    if expires_at <= issued_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="expires_at must be after issued_at",
        )
    if issued_at - now > timedelta(seconds=settings.allowed_clock_skew_seconds):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="issued_at is too far in the future",
        )
    if now > expires_at:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Payload has expired")


def _store_nonce(
    db: Session,
    *,
    principal_id: str,
    nonce: str,
    purpose: str,
    settings: Settings,
) -> None:
    existing = (
        db.query(ReplayNonce)
        .filter(
            ReplayNonce.principal_id == principal_id,
            ReplayNonce.nonce == nonce,
            ReplayNonce.purpose == purpose,
        )
        .first()
    )
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Replay detected")
    db.add(
        ReplayNonce(
            principal_id=principal_id,
            nonce=nonce,
            purpose=purpose,
            expires_at=utcnow() + timedelta(seconds=settings.nonce_ttl_seconds),
        )
    )
    db.flush()


def _load_active_principal(db: Session, principal_id: str) -> Principal:
    principal = db.query(Principal).filter(Principal.principal_id == principal_id).first()
    if principal is None or not principal.active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown principal: {principal_id}",
        )
    return principal


def create_message(
    db: Session,
    *,
    payload: MessageEnvelopeIn,
    authenticated_principal: Principal,
    settings: Settings,
) -> MessageEnvelope:
    if authenticated_principal.principal_id != payload.sender_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Sender mismatch")
    sender = authenticated_principal
    recipient = _load_active_principal(db, payload.recipient_id)
    require_scope(sender, "message:send")
    _validate_temporal_window(payload.issued_at, payload.expires_at, settings)
    _store_nonce(
        db,
        principal_id=sender.principal_id,
        nonce=payload.nonce,
        purpose="message",
        settings=settings,
    )

    verify_payload = canonical_json(payload.model_dump(exclude={"signature"}))
    if not safe_verify(sender.public_signing_key, verify_payload, payload.signature):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bad envelope signature",
        )

    existing = db.query(MessageEnvelope).filter(
        MessageEnvelope.message_id == payload.message_id
    ).first()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="message_id already exists",
        )

    envelope = MessageEnvelope(
        message_id=payload.message_id,
        sender_id=sender.principal_id,
        recipient_id=recipient.principal_id,
        conversation_id=payload.conversation_id,
        content_type=payload.content_type,
        ciphertext=payload.ciphertext,
        nonce=payload.nonce,
        signature=payload.signature,
        payload_hash=sha256_hex(payload.ciphertext),
        metadata_json=json.dumps(payload.metadata, sort_keys=True),
        issued_at=to_utc(payload.issued_at),
        expires_at=to_utc(payload.expires_at),
    )
    db.add(envelope)
    db.flush()
    append_audit_event(
        db,
        event_type="message.accepted",
        subject_type="message",
        subject_id=envelope.message_id,
        actor_id=sender.principal_id,
        payload={"recipient_id": recipient.principal_id, "payload_hash": envelope.payload_hash},
    )
    return envelope


def list_inbox(db: Session, *, recipient: Principal) -> list[MessageEnvelope]:
    require_scope(recipient, "message:receive")
    envelopes = (
        db.query(MessageEnvelope)
        .filter(
            MessageEnvelope.recipient_id == recipient.principal_id,
            MessageEnvelope.status.in_(["pending", "delivered"]),
        )
        .order_by(MessageEnvelope.created_at.asc())
        .all()
    )
    for envelope in envelopes:
        if envelope.status == "pending":
            envelope.status = "delivered"
            envelope.delivery_count += 1
            append_audit_event(
                db,
                event_type="message.delivered",
                subject_type="message",
                subject_id=envelope.message_id,
                actor_id=recipient.principal_id,
                payload={"delivery_count": envelope.delivery_count},
            )
    db.flush()
    return envelopes


def acknowledge_message(
    db: Session,
    *,
    recipient: Principal,
    message_id: str,
    payload: MessageEnvelopeAck,
    settings: Settings,
) -> MessageEnvelope:
    require_scope(recipient, "message:ack")
    envelope = db.query(MessageEnvelope).filter(MessageEnvelope.message_id == message_id).first()
    if envelope is None or envelope.recipient_id != recipient.principal_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found")

    _store_nonce(
        db,
        principal_id=recipient.principal_id,
        nonce=payload.nonce,
        purpose="message-ack",
        settings=settings,
    )
    signed_payload = canonical_json(
        {
            "message_id": message_id,
            "recipient_id": recipient.principal_id,
            "nonce": payload.nonce,
            "payload_hash": envelope.payload_hash,
        }
    )
    if not safe_verify(recipient.public_signing_key, signed_payload, payload.signature):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bad ack signature")

    envelope.status = "acknowledged"
    envelope.ack_signature = payload.signature
    append_audit_event(
        db,
        event_type="message.acknowledged",
        subject_type="message",
        subject_id=envelope.message_id,
        actor_id=recipient.principal_id,
        payload={"payload_hash": envelope.payload_hash},
    )
    db.flush()
    return envelope


def create_action_request(
    db: Session,
    *,
    payload: ActionRequestIn,
    requester: Principal,
    settings: Settings,
) -> ActionRequest:
    if requester.principal_id != payload.sender_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Sender mismatch")
    target = _load_active_principal(db, payload.target_id)
    require_scope(requester, f"action:{payload.action_type}")
    _validate_temporal_window(payload.issued_at, payload.expires_at, settings)
    _store_nonce(
        db,
        principal_id=requester.principal_id,
        nonce=payload.nonce,
        purpose="action",
        settings=settings,
    )

    verify_payload = canonical_json(payload.model_dump(exclude={"signature"}))
    if not safe_verify(requester.public_signing_key, verify_payload, payload.signature):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bad action signature")

    existing = db.query(ActionRequest).filter(
        ActionRequest.request_id == payload.request_id
    ).first()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="request_id already exists",
        )

    provisional = ActionRequest(required_approvals=1)
    required_approvals = required_approvals_for_action(
        provisional,
        target,
        settings,
        payload.risk_level,
    )
    action = ActionRequest(
        request_id=payload.request_id,
        sender_id=requester.principal_id,
        target_id=target.principal_id,
        action_type=payload.action_type,
        resource=payload.resource,
        risk_level=payload.risk_level,
        ciphertext=payload.ciphertext,
        nonce=payload.nonce,
        signature=payload.signature,
        metadata_json=json.dumps(payload.metadata, sort_keys=True),
        issued_at=to_utc(payload.issued_at),
        expires_at=to_utc(payload.expires_at),
        required_approvals=required_approvals,
        status="approved" if required_approvals == 0 else "requested",
    )
    db.add(action)
    db.flush()
    append_audit_event(
        db,
        event_type="action.requested",
        subject_type="action",
        subject_id=action.request_id,
        actor_id=requester.principal_id,
        payload={
            "target_id": target.principal_id,
            "action_type": action.action_type,
            "risk_level": action.risk_level,
            "required_approvals": required_approvals,
        },
    )
    return action


def approve_action(
    db: Session,
    *,
    request_id: str,
    payload: ActionApprovalIn,
    approver: Principal,
    settings: Settings,
) -> ActionRequest:
    if approver.principal_id != payload.approver_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Approver mismatch")
    action = db.query(ActionRequest).filter(ActionRequest.request_id == request_id).first()
    if action is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Action not found")
    if action.status in {"executed", "rejected"}:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Action is closed")

    scope = f"approve:{action.action_type}"
    if not (scope_allows(approver, scope) or scope_allows(approver, "approve:*")):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Approver lacks scope")
    _store_nonce(
        db,
        principal_id=approver.principal_id,
        nonce=payload.nonce,
        purpose="action-approval",
        settings=settings,
    )
    signed_payload = canonical_json(
        {
            "request_id": request_id,
            "approver_id": approver.principal_id,
            "decision": payload.decision,
            "reason": payload.reason,
            "nonce": payload.nonce,
        }
    )
    if not safe_verify(approver.public_signing_key, signed_payload, payload.signature):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bad approval signature",
        )

    existing = (
        db.query(ActionApproval)
        .filter(
            ActionApproval.action_request_id == action.id,
            ActionApproval.approver_id == approver.principal_id,
        )
        .first()
    )
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Approver already voted")

    approval = ActionApproval(
        action_request_id=action.id,
        approver_id=approver.principal_id,
        decision=payload.decision,
        reason=payload.reason,
        nonce=payload.nonce,
        signature=payload.signature,
    )
    db.add(approval)
    db.flush()

    decisions = [item.decision for item in action.approvals]
    if "rejected" in decisions:
        action.status = "rejected"
    elif decisions.count("approved") >= action.required_approvals:
        action.status = "approved"

    append_audit_event(
        db,
        event_type=f"action.{payload.decision}",
        subject_type="action",
        subject_id=action.request_id,
        actor_id=approver.principal_id,
        payload={"reason": payload.reason},
    )
    db.flush()
    return action


def execute_action(
    db: Session,
    *,
    request_id: str,
    payload: ActionExecutionIn,
    executor: Principal,
    settings: Settings,
) -> ActionRequest:
    if executor.principal_id != payload.executor_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Executor mismatch")
    action = db.query(ActionRequest).filter(ActionRequest.request_id == request_id).first()
    if action is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Action not found")
    if action.target_id != executor.principal_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Wrong executor")
    if action.status != "approved":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Action is not approved")
    if utcnow() > to_utc(action.expires_at):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Action request has expired",
        )

    require_scope(executor, f"execute:{action.action_type}")
    _store_nonce(
        db,
        principal_id=executor.principal_id,
        nonce=payload.nonce,
        purpose="action-execution",
        settings=settings,
    )
    signed_payload = canonical_json(
        {
            "request_id": request_id,
            "executor_id": executor.principal_id,
            "nonce": payload.nonce,
            "execution_receipt": payload.execution_receipt,
        }
    )
    if not safe_verify(executor.public_signing_key, signed_payload, payload.signature):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bad execution signature",
        )

    action.status = "executed"
    action.executed_at = utcnow()
    metadata = json.loads(action.metadata_json)
    metadata["execution_receipt"] = payload.execution_receipt
    action.metadata_json = json.dumps(metadata, sort_keys=True)
    append_audit_event(
        db,
        event_type="action.executed",
        subject_type="action",
        subject_id=action.request_id,
        actor_id=executor.principal_id,
        payload={"execution_receipt": payload.execution_receipt},
    )
    db.flush()
    return action
