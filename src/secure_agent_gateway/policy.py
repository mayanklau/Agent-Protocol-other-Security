import json

from secure_agent_gateway.config import Settings
from secure_agent_gateway.models import ActionRequest, Principal


def scopes_for(principal: Principal) -> set[str]:
    return set(json.loads(principal.scopes_json))


def scope_allows(principal: Principal, required_scope: str) -> bool:
    scopes = scopes_for(principal)
    if "*" in scopes:
        return True
    return required_scope in scopes


def require_scope(principal: Principal, required_scope: str) -> None:
    if not scope_allows(principal, required_scope):
        raise PermissionError(f"{principal.principal_id} lacks scope {required_scope}")


def required_approvals_for_action(
    request: ActionRequest | None,
    target_principal: Principal,
    settings: Settings,
    risk_level: str,
) -> int:
    baseline = max(settings.action_default_approvals, target_principal.min_approvals)
    if risk_level == "high":
        baseline = max(baseline, settings.high_risk_action_approvals)
    if risk_level == "critical":
        baseline = max(baseline, settings.critical_risk_action_approvals)
    if request is not None:
        baseline = max(baseline, request.required_approvals)
    return baseline
