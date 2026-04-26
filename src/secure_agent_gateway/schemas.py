from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class PrincipalRegistration(BaseModel):
    principal_id: str = Field(min_length=3, max_length=128)
    kind: Literal["agent", "service", "human-approver"]
    display_name: str = Field(min_length=1, max_length=255)
    public_signing_key: str = Field(min_length=32)
    public_encryption_key: str | None = None
    scopes: list[str] = Field(default_factory=list)
    min_approvals: int = Field(default=1, ge=1, le=10)


class PrincipalResponse(BaseModel):
    principal_id: str
    kind: str
    display_name: str
    public_signing_key: str
    public_encryption_key: str | None
    scopes: list[str]
    min_approvals: int
    active: bool
    created_at: datetime


class MessageEnvelopeIn(BaseModel):
    message_id: str = Field(min_length=8, max_length=128)
    sender_id: str
    recipient_id: str
    conversation_id: str | None = None
    content_type: str = Field(default="application/octet-stream", max_length=128)
    ciphertext: str = Field(min_length=8)
    nonce: str = Field(min_length=8, max_length=255)
    metadata: dict[str, Any] = Field(default_factory=dict)
    issued_at: datetime
    expires_at: datetime
    signature: str = Field(min_length=32)


class MessageEnvelopeAck(BaseModel):
    nonce: str = Field(min_length=8, max_length=255)
    signature: str = Field(min_length=32)


class MessageEnvelopeOut(BaseModel):
    message_id: str
    sender_id: str
    recipient_id: str
    conversation_id: str | None
    content_type: str
    ciphertext: str
    metadata: dict[str, Any]
    issued_at: datetime
    expires_at: datetime
    status: str


class ActionRequestIn(BaseModel):
    request_id: str = Field(min_length=8, max_length=128)
    sender_id: str
    target_id: str
    action_type: str = Field(min_length=3, max_length=128)
    resource: str = Field(min_length=1, max_length=255)
    risk_level: Literal["low", "medium", "high", "critical"]
    ciphertext: str = Field(min_length=8)
    nonce: str = Field(min_length=8, max_length=255)
    metadata: dict[str, Any] = Field(default_factory=dict)
    issued_at: datetime
    expires_at: datetime
    signature: str = Field(min_length=32)


class ActionApprovalIn(BaseModel):
    approver_id: str
    decision: Literal["approved", "rejected"]
    reason: str | None = None
    nonce: str = Field(min_length=8, max_length=255)
    signature: str = Field(min_length=32)


class ActionExecutionIn(BaseModel):
    executor_id: str
    nonce: str = Field(min_length=8, max_length=255)
    execution_receipt: dict[str, Any] = Field(default_factory=dict)
    signature: str = Field(min_length=32)


class ActionStatusOut(BaseModel):
    request_id: str
    sender_id: str
    target_id: str
    action_type: str
    resource: str
    risk_level: str
    status: str
    required_approvals: int
    approvals: list[dict[str, Any]]
    metadata: dict[str, Any]
    executed_at: datetime | None


class AuditEventOut(BaseModel):
    event_type: str
    subject_type: str
    subject_id: str
    actor_id: str | None
    payload: dict[str, Any]
    prev_hash: str | None
    event_hash: str
    created_at: datetime
