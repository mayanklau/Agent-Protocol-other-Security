from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from secure_agent_gateway.crypto import utcnow
from secure_agent_gateway.db import Base


class Principal(Base):
    __tablename__ = "principals"

    id: Mapped[int] = mapped_column(primary_key=True)
    principal_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    kind: Mapped[str] = mapped_column(String(32))
    display_name: Mapped[str] = mapped_column(String(255))
    public_signing_key: Mapped[str] = mapped_column(Text)
    public_encryption_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    scopes_json: Mapped[str] = mapped_column(Text, default="[]")
    min_approvals: Mapped[int] = mapped_column(Integer, default=1)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped["datetime"] = mapped_column(DateTime(timezone=True), default=utcnow)


class ReplayNonce(Base):
    __tablename__ = "replay_nonces"
    __table_args__ = (UniqueConstraint("principal_id", "nonce", "purpose"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    principal_id: Mapped[str] = mapped_column(String(128), index=True)
    nonce: Mapped[str] = mapped_column(String(255))
    purpose: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped["datetime"] = mapped_column(DateTime(timezone=True), default=utcnow)


class MessageEnvelope(Base):
    __tablename__ = "message_envelopes"

    id: Mapped[int] = mapped_column(primary_key=True)
    message_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    sender_id: Mapped[str] = mapped_column(String(128), index=True)
    recipient_id: Mapped[str] = mapped_column(String(128), index=True)
    conversation_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    content_type: Mapped[str] = mapped_column(String(128))
    ciphertext: Mapped[str] = mapped_column(Text)
    nonce: Mapped[str] = mapped_column(String(255))
    signature: Mapped[str] = mapped_column(Text)
    payload_hash: Mapped[str] = mapped_column(String(128))
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    delivery_count: Mapped[int] = mapped_column(Integer, default=0)
    ack_signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped["datetime"] = mapped_column(DateTime(timezone=True), default=utcnow)


class ActionRequest(Base):
    __tablename__ = "action_requests"

    id: Mapped[int] = mapped_column(primary_key=True)
    request_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    sender_id: Mapped[str] = mapped_column(String(128), index=True)
    target_id: Mapped[str] = mapped_column(String(128), index=True)
    action_type: Mapped[str] = mapped_column(String(128), index=True)
    resource: Mapped[str] = mapped_column(String(255))
    risk_level: Mapped[str] = mapped_column(String(32))
    ciphertext: Mapped[str] = mapped_column(Text)
    nonce: Mapped[str] = mapped_column(String(255))
    signature: Mapped[str] = mapped_column(Text)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    issued_at: Mapped["datetime"] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped["datetime"] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(32), default="requested", index=True)
    required_approvals: Mapped[int] = mapped_column(Integer, default=1)
    executed_at: Mapped["datetime | None"] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped["datetime"] = mapped_column(DateTime(timezone=True), default=utcnow)

    approvals: Mapped[list["ActionApproval"]] = relationship(back_populates="action")


class ActionApproval(Base):
    __tablename__ = "action_approvals"
    __table_args__ = (UniqueConstraint("action_request_id", "approver_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    action_request_id: Mapped[int] = mapped_column(ForeignKey("action_requests.id"), index=True)
    approver_id: Mapped[str] = mapped_column(String(128), index=True)
    decision: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    nonce: Mapped[str] = mapped_column(String(255))
    signature: Mapped[str] = mapped_column(Text)
    created_at: Mapped["datetime"] = mapped_column(DateTime(timezone=True), default=utcnow)

    action: Mapped[ActionRequest] = relationship(back_populates="approvals")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    event_type: Mapped[str] = mapped_column(String(128), index=True)
    subject_type: Mapped[str] = mapped_column(String(64))
    subject_id: Mapped[str] = mapped_column(String(128), index=True)
    actor_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    payload_json: Mapped[str] = mapped_column(Text)
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped["datetime"] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        index=True,
    )
