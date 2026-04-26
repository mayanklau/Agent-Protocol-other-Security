# Secure Agent Gateway

Secure Agent Gateway is a production-shaped FastAPI service that protects agent-to-agent communication and action execution with signed requests, replay protection, approval workflows, and tamper-evident audit trails.

## What it secures

- End-to-end agent messaging with signed envelopes and recipient acknowledgements.
- Action requests such as deploy, tool invocation, or data mutation with policy checks and approval thresholds.
- Replay defense through nonce tracking on both HTTP requests and business payloads.
- Tamper-evident audit logging through a hash chain of all critical events.
- Separation of duties by requiring different principals for requester, approver, and executor roles.

## Security model

- Each principal registers an Ed25519 public signing key.
- Every API call is authenticated with `X-Principal-Id`, `X-Timestamp`, `X-Nonce`, and `X-Signature`.
- Message and action bodies are independently signed, so transport authentication and business authorization are both enforced.
- Ciphertext is stored and relayed as opaque payload data, which keeps the gateway compatible with end-to-end encryption between agents.
- High-risk and critical actions can require multiple approvals before execution.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
cp .env.example .env
uvicorn secure_agent_gateway.main:app --reload
```

Open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) for the API docs.

## API surface

- `POST /v1/principals`: register agent, service, or human approver identities. Requires `X-Admin-Token`.
- `POST /v1/messages`: submit a signed encrypted envelope from one principal to another.
- `GET /v1/messages/inbox/{recipient_id}`: fetch the authenticated recipient inbox.
- `POST /v1/messages/{message_id}/ack`: acknowledge receipt with a signed acknowledgement.
- `POST /v1/actions`: request execution of a sensitive action.
- `POST /v1/actions/{request_id}/approvals`: approve or reject an action request.
- `POST /v1/actions/{request_id}/execute`: execute an approved action as the designated target principal.
- `GET /v1/audit`: inspect the tamper-evident audit trail. Requires `X-Admin-Token`.

## Production hardening checklist

- Put the service behind TLS termination or a service mesh with mTLS.
- Store the database on durable encrypted storage and rotate backups.
- Keep private signing keys in HSM/KMS or agent-local secure enclaves.
- Replace the bootstrap admin token with secret-manager backed configuration.
- Add outbound delivery adapters for your agent runtime, queue, or workflow engine.
- Extend policy decisions with resource-level allowlists and environment-aware gates.

## Testing

```bash
pytest
ruff check .
```

## Push to GitHub

```bash
git add .
git commit -m "Build secure agent gateway"
git push origin main
```
