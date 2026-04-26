import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

os.environ["SAG_DATABASE_URL"] = "sqlite+pysqlite:///:memory:"
os.environ["SAG_ADMIN_TOKEN"] = "test-admin-token"

from secure_agent_gateway.crypto import (  # noqa: E402
    canonical_json,
    generate_keypair,
    sha256_hex,
    sign_payload,
)
from secure_agent_gateway.db import Base, engine  # noqa: E402
from secure_agent_gateway.main import app  # noqa: E402


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def now() -> datetime:
    return datetime.now(UTC)


def register_principal(client, principal_id, public_key, scopes, kind="agent", min_approvals=1):
    response = client.post(
        "/v1/principals",
        headers={"X-Admin-Token": "test-admin-token"},
        json={
            "principal_id": principal_id,
            "kind": kind,
            "display_name": principal_id,
            "public_signing_key": public_key,
            "public_encryption_key": None,
            "scopes": scopes,
            "min_approvals": min_approvals,
        },
    )
    assert response.status_code == 200, response.text


def signed_headers(private_key, principal_id, method, path, body):
    timestamp = now().isoformat()
    nonce = str(uuid4())
    body_hash = sha256_hex(body)
    signature = sign_payload(
        private_key,
        f"{method}|{path}|{timestamp}|{nonce}|{body_hash}".encode(),
    )
    return {
        "X-Principal-Id": principal_id,
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "X-Signature": signature,
    }


def test_message_flow_and_ack(client):
    sender_private, sender_public = generate_keypair()
    recipient_private, recipient_public = generate_keypair()
    register_principal(client, "agent-alpha", sender_public, ["message:send"])
    register_principal(client, "agent-beta", recipient_public, ["message:receive", "message:ack"])

    payload = {
        "message_id": "msg-0001",
        "sender_id": "agent-alpha",
        "recipient_id": "agent-beta",
        "conversation_id": "conv-1",
        "content_type": "application/agent-envelope+json",
        "ciphertext": "ZW5jcnlwdGVk",
        "nonce": "msg-nonce-1",
        "metadata": {"classification": "restricted"},
        "issued_at": now().isoformat(),
        "expires_at": (now() + timedelta(minutes=5)).isoformat(),
    }
    payload["signature"] = sign_payload(sender_private, canonical_json(payload))
    headers = signed_headers(
        sender_private,
        "agent-alpha",
        "POST",
        "/v1/messages",
        canonical_json(payload),
    )
    response = client.post("/v1/messages", headers=headers, json=payload)
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "pending"

    inbox_headers = signed_headers(
        recipient_private, "agent-beta", "GET", "/v1/messages/inbox/agent-beta", b""
    )
    inbox = client.get("/v1/messages/inbox/agent-beta", headers=inbox_headers)
    assert inbox.status_code == 200, inbox.text
    assert len(inbox.json()) == 1
    assert inbox.json()[0]["message_id"] == "msg-0001"
    assert inbox.json()[0]["status"] == "delivered"

    ack_payload = {
        "nonce": "ack-nonce-1",
    }
    ack_payload["signature"] = sign_payload(
        recipient_private,
        canonical_json(
            {
                "message_id": "msg-0001",
                "recipient_id": "agent-beta",
                "nonce": ack_payload["nonce"],
                "payload_hash": sha256_hex("ZW5jcnlwdGVk"),
            }
        ),
    )
    ack_headers = signed_headers(
        recipient_private,
        "agent-beta",
        "POST",
        "/v1/messages/msg-0001/ack",
        canonical_json(ack_payload),
    )
    ack = client.post("/v1/messages/msg-0001/ack", headers=ack_headers, json=ack_payload)
    assert ack.status_code == 200, ack.text
    assert ack.json()["status"] == "acknowledged"


def test_replay_defense_blocks_duplicate_message_nonce(client):
    sender_private, sender_public = generate_keypair()
    recipient_private, recipient_public = generate_keypair()
    register_principal(client, "sender", sender_public, ["message:send"])
    register_principal(client, "recipient", recipient_public, ["message:receive", "message:ack"])

    payload = {
        "message_id": "msg-replay-1",
        "sender_id": "sender",
        "recipient_id": "recipient",
        "conversation_id": None,
        "content_type": "application/octet-stream",
        "ciphertext": "Y2lwaGVy",
        "nonce": "reused-message-nonce",
        "metadata": {},
        "issued_at": now().isoformat(),
        "expires_at": (now() + timedelta(minutes=5)).isoformat(),
    }
    payload["signature"] = sign_payload(sender_private, canonical_json(payload))
    first_headers = signed_headers(
        sender_private,
        "sender",
        "POST",
        "/v1/messages",
        canonical_json(payload),
    )
    second_headers = signed_headers(
        sender_private,
        "sender",
        "POST",
        "/v1/messages",
        canonical_json(payload),
    )

    first = client.post("/v1/messages", headers=first_headers, json=payload)
    assert first.status_code == 200, first.text

    payload["message_id"] = "msg-replay-22"
    payload["signature"] = sign_payload(
        sender_private,
        canonical_json({key: value for key, value in payload.items() if key != "signature"}),
    )
    second_headers = signed_headers(
        sender_private,
        "sender",
        "POST",
        "/v1/messages",
        canonical_json(payload),
    )
    second = client.post("/v1/messages", headers=second_headers, json=payload)
    assert second.status_code == 409, second.text


def test_high_risk_action_requires_approvals_and_executes(client):
    requester_private, requester_public = generate_keypair()
    executor_private, executor_public = generate_keypair()
    approver1_private, approver1_public = generate_keypair()
    approver2_private, approver2_public = generate_keypair()

    register_principal(client, "planner", requester_public, ["action:deploy"])
    register_principal(client, "executor", executor_public, ["execute:deploy"], min_approvals=2)
    register_principal(
        client,
        "approver-1",
        approver1_public,
        ["approve:deploy"],
        kind="human-approver",
    )
    register_principal(
        client,
        "approver-2",
        approver2_public,
        ["approve:deploy"],
        kind="human-approver",
    )

    action_payload = {
        "request_id": "act-0001",
        "sender_id": "planner",
        "target_id": "executor",
        "action_type": "deploy",
        "resource": "prod/service-a",
        "risk_level": "high",
        "ciphertext": "YWN0aW9uLXBheWxvYWQ=",
        "nonce": "action-nonce-1",
        "metadata": {"change_ticket": "CHG-42"},
        "issued_at": now().isoformat(),
        "expires_at": (now() + timedelta(minutes=5)).isoformat(),
    }
    action_payload["signature"] = sign_payload(requester_private, canonical_json(action_payload))
    action_headers = signed_headers(
        requester_private, "planner", "POST", "/v1/actions", canonical_json(action_payload)
    )
    created = client.post("/v1/actions", headers=action_headers, json=action_payload)
    assert created.status_code == 200, created.text
    assert created.json()["required_approvals"] == 2
    assert created.json()["status"] == "requested"

    for approver_id, private_key in [
        ("approver-1", approver1_private),
        ("approver-2", approver2_private),
    ]:
        approval_payload = {
            "approver_id": approver_id,
            "decision": "approved",
            "reason": "Looks good",
            "nonce": f"{approver_id}-nonce",
        }
        approval_payload["signature"] = sign_payload(
            private_key,
            canonical_json(
                {
                    "request_id": "act-0001",
                    "approver_id": approver_id,
                    "decision": "approved",
                    "reason": "Looks good",
                    "nonce": approval_payload["nonce"],
                }
            ),
        )
        approval_headers = signed_headers(
            private_key,
            approver_id,
            "POST",
            "/v1/actions/act-0001/approvals",
            canonical_json(approval_payload),
        )
        approval = client.post(
            "/v1/actions/act-0001/approvals",
            headers=approval_headers,
            json=approval_payload,
        )
        assert approval.status_code == 200, approval.text

    execution_payload = {
        "executor_id": "executor",
        "nonce": "executor-nonce-1",
        "execution_receipt": {"job_id": "job-123", "status": "success"},
    }
    execution_payload["signature"] = sign_payload(
        executor_private,
        canonical_json(
            {
                "request_id": "act-0001",
                "executor_id": "executor",
                "nonce": "executor-nonce-1",
                "execution_receipt": execution_payload["execution_receipt"],
            }
        ),
    )
    execution_headers = signed_headers(
        executor_private,
        "executor",
        "POST",
        "/v1/actions/act-0001/execute",
        canonical_json(execution_payload),
    )
    executed = client.post(
        "/v1/actions/act-0001/execute",
        headers=execution_headers,
        json=execution_payload,
    )
    assert executed.status_code == 200, executed.text
    assert executed.json()["status"] == "executed"
    assert executed.json()["metadata"]["execution_receipt"]["job_id"] == "job-123"
