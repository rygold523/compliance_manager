from app.services.ai_provider import call_ai_json
from app.services.ai_guardrails import enforce_ai_guardrails

PROMPT = "You are a defensive compliance finding analyzer. Return JSON only. Do not execute commands or approve changes."

def analyze_finding_with_ai(finding_payload: dict, deterministic_mapping: dict | None = None) -> dict:
    return enforce_ai_guardrails(call_ai_json(PROMPT, {"finding": finding_payload, "deterministic_mapping": deterministic_mapping or {}}))
