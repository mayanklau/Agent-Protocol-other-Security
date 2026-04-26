import json
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session

from secure_agent_gateway.config import Settings, get_settings
from secure_agent_gateway.db import get_db, init_db
from secure_agent_gateway.models import ActionRequest, AuditEvent, MessageEnvelope, Principal
from secure_agent_gateway.schemas import (
    ActionApprovalIn,
    ActionExecutionIn,
    ActionRequestIn,
    ActionStatusOut,
    AuditEventOut,
    MessageEnvelopeAck,
    MessageEnvelopeIn,
    MessageEnvelopeOut,
    PrincipalRegistration,
    PrincipalResponse,
)
from secure_agent_gateway.security import admin_guard, signed_request_guard
from secure_agent_gateway.service import (
    acknowledge_message,
    approve_action,
    create_action_request,
    create_message,
    execute_action,
    list_inbox,
    register_principal,
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="Secure Agent Gateway", version="0.1.0", lifespan=lifespan)


@app.get("/healthz")
def healthz(settings: Settings = Depends(get_settings)) -> dict[str, str]:
    return {"status": "ok", "environment": settings.environment}


@app.post("/v1/principals", response_model=PrincipalResponse, dependencies=[Depends(admin_guard)])
def create_principal(payload: PrincipalRegistration, db: Session = Depends(get_db)) -> Principal:
    principal = register_principal(db, payload)
    db.commit()
    return serialize_principal(principal)


@app.post("/v1/messages", response_model=MessageEnvelopeOut)
def submit_message(
    payload: MessageEnvelopeIn,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    principal: Principal = Depends(signed_request_guard),
) -> MessageEnvelope:
    envelope = create_message(
        db,
        payload=payload,
        authenticated_principal=principal,
        settings=settings,
    )
    db.commit()
    return serialize_message(envelope)


@app.get("/v1/messages/inbox/{recipient_id}", response_model=list[MessageEnvelopeOut])
def get_inbox(
    recipient_id: str,
    db: Session = Depends(get_db),
    principal: Principal = Depends(signed_request_guard),
) -> list[MessageEnvelope]:
    if principal.principal_id != recipient_id:
        raise HTTPException(status_code=403, detail="Principal may only read its own inbox")
    envelopes = list_inbox(db, recipient=principal)
    db.commit()
    return [serialize_message(item) for item in envelopes]


@app.post("/v1/messages/{message_id}/ack", response_model=MessageEnvelopeOut)
def ack_message(
    message_id: str,
    payload: MessageEnvelopeAck,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    principal: Principal = Depends(signed_request_guard),
) -> MessageEnvelope:
    envelope = acknowledge_message(
        db, recipient=principal, message_id=message_id, payload=payload, settings=settings
    )
    db.commit()
    return serialize_message(envelope)


@app.post("/v1/actions", response_model=ActionStatusOut)
def submit_action(
    payload: ActionRequestIn,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    principal: Principal = Depends(signed_request_guard),
) -> ActionRequest:
    action = create_action_request(db, payload=payload, requester=principal, settings=settings)
    db.commit()
    db.refresh(action)
    return serialize_action(action)


@app.post("/v1/actions/{request_id}/approvals", response_model=ActionStatusOut)
def add_approval(
    request_id: str,
    payload: ActionApprovalIn,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    principal: Principal = Depends(signed_request_guard),
) -> ActionRequest:
    action = approve_action(
        db,
        request_id=request_id,
        payload=payload,
        approver=principal,
        settings=settings,
    )
    db.commit()
    db.refresh(action)
    return serialize_action(action)


@app.post("/v1/actions/{request_id}/execute", response_model=ActionStatusOut)
def execute(
    request_id: str,
    payload: ActionExecutionIn,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    principal: Principal = Depends(signed_request_guard),
) -> ActionRequest:
    action = execute_action(
        db,
        request_id=request_id,
        payload=payload,
        executor=principal,
        settings=settings,
    )
    db.commit()
    db.refresh(action)
    return serialize_action(action)


@app.get("/v1/actions/{request_id}", response_model=ActionStatusOut)
def get_action(
    request_id: str,
    db: Session = Depends(get_db),
    _: Principal = Depends(signed_request_guard),
) -> ActionRequest:
    action = db.query(ActionRequest).filter(ActionRequest.request_id == request_id).first()
    if action is None:
        raise HTTPException(status_code=404, detail="Action not found")
    return serialize_action(action)


@app.get("/v1/audit", response_model=list[AuditEventOut], dependencies=[Depends(admin_guard)])
def list_audit_events(db: Session = Depends(get_db), limit: int = 100) -> list[AuditEvent]:
    events = (
        db.query(AuditEvent)
        .order_by(AuditEvent.created_at.desc())
        .limit(min(limit, 500))
        .all()
    )
    return [serialize_audit(item) for item in events]


def serialize_principal(principal: Principal) -> PrincipalResponse:
    return PrincipalResponse(
        principal_id=principal.principal_id,
        kind=principal.kind,
        display_name=principal.display_name,
        public_signing_key=principal.public_signing_key,
        public_encryption_key=principal.public_encryption_key,
        scopes=json.loads(principal.scopes_json),
        min_approvals=principal.min_approvals,
        active=principal.active,
        created_at=principal.created_at,
    )


def serialize_message(message: MessageEnvelope) -> MessageEnvelopeOut:
    return MessageEnvelopeOut(
        message_id=message.message_id,
        sender_id=message.sender_id,
        recipient_id=message.recipient_id,
        conversation_id=message.conversation_id,
        content_type=message.content_type,
        ciphertext=message.ciphertext,
        metadata=json.loads(message.metadata_json),
        issued_at=message.issued_at,
        expires_at=message.expires_at,
        status=message.status,
    )


def serialize_action(action: ActionRequest) -> ActionStatusOut:
    return ActionStatusOut(
        request_id=action.request_id,
        sender_id=action.sender_id,
        target_id=action.target_id,
        action_type=action.action_type,
        resource=action.resource,
        risk_level=action.risk_level,
        status=action.status,
        required_approvals=action.required_approvals,
        approvals=[
            {
                "approver_id": item.approver_id,
                "decision": item.decision,
                "reason": item.reason,
                "created_at": item.created_at,
            }
            for item in action.approvals
        ],
        metadata=json.loads(action.metadata_json),
        executed_at=action.executed_at,
    )


def serialize_audit(event: AuditEvent) -> AuditEventOut:
    return AuditEventOut(
        event_type=event.event_type,
        subject_type=event.subject_type,
        subject_id=event.subject_id,
        actor_id=event.actor_id,
        payload=json.loads(event.payload_json),
        prev_hash=event.prev_hash,
        event_hash=event.event_hash,
        created_at=event.created_at,
    )
