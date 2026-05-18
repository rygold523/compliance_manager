from datetime import datetime, timezone
from typing import Any, Dict


def normalize_twilio_event(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "event_type": payload.get("EventType") or payload.get("event_type"),
        "message_sid": payload.get("MessageSid") or payload.get("message_sid"),
        "to": payload.get("To") or payload.get("to"),
        "from": payload.get("From") or payload.get("from"),
        "status": payload.get("MessageStatus") or payload.get("status"),
        "error_code": payload.get("ErrorCode") or payload.get("error_code"),
        "received_at": datetime.now(timezone.utc).isoformat(),
        "raw_payload": payload,
    }
