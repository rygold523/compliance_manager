def enforce_ai_guardrails(ai_response: dict) -> dict:
    if not isinstance(ai_response, dict):
        return {"response": "Invalid AI response.", "requires_approval": False}
    action_data = ai_response.get("recommended_action") or {}
    if not isinstance(action_data, dict):
        action_data = {}
    action = action_data.get("type") or ai_response.get("action") or ""
    blocked = {"execute_command", "approve_remediation", "apply_nginx_config", "service_reload", "service_restart", "docker_image_rebuild", "docker_image_rebuilds", "direct_database_change"}
    if action in blocked:
        action_data["safe_to_auto_apply"] = False
        action_data["approval_required"] = True
        action_data["blocked_by_guardrail"] = True
        ai_response["recommended_action"] = action_data
        ai_response["requires_approval"] = True
    return ai_response
