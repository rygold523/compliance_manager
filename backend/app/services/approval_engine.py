from app.core.config import settings

PROTECTED_ACTIONS = {"package_update", "update_unheld_packages", "nginx_config_change", "service_reload", "service_restart", "config_change"}

def requires_approval(environment: str, action_type: str) -> bool:
    if environment.lower() == "production" and settings.require_approval_for_production:
        return True
    return action_type in PROTECTED_ACTIONS

def validate_action_policy(asset, action_type: str) -> tuple[bool, str]:
    blocked = asset.blocked_actions or []
    allowed = asset.allowed_actions or {}

    if action_type in blocked:
        return False, f"Action is explicitly blocked for asset: {action_type}"
    if action_type == "docker_image_rebuilds":
        return False, "Docker image rebuilds are disabled."
    if allowed.get(action_type) == "approval_required":
        return False, f"Approval required for action: {action_type}"
    if requires_approval(asset.environment, action_type):
        return False, f"Approval required for {asset.environment} action: {action_type}"
    return True, "Allowed"
