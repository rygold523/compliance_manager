import json
import requests
from app.core.config import settings

def call_ai_json(system_prompt: str, user_payload: dict) -> dict:
    if not settings.ai_enabled:
        return {"response": "AI is disabled.", "requires_approval": False}
    payload = {
        "model": settings.ai_model,
        "stream": False,
        "format": "json",
        "system": system_prompt,
        "prompt": json.dumps(user_payload, indent=2, default=str),
        "options": {"temperature": settings.ai_temperature, "num_predict": settings.ai_max_tokens},
    }
    try:
        response = requests.post(f"{settings.ai_base_url}/api/generate", json=payload, timeout=300)
        response.raise_for_status()
        return json.loads(response.json().get("response", "{}"))
    except Exception as exc:
        return {"response": f"Local AI request failed: {exc}", "error": str(exc), "requires_approval": False}
