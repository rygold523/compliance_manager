import os

ENABLE_REGULATORY_ENGINE = os.getenv("ENABLE_REGULATORY_ENGINE", "false").lower() == "true"
ENABLE_TWILIO_VALIDATION = os.getenv("ENABLE_TWILIO_VALIDATION", "false").lower() == "true"
ENABLE_DRIFT_ENGINE = os.getenv("ENABLE_DRIFT_ENGINE", "false").lower() == "true"
ENABLE_POLICY_ENGINE = os.getenv("ENABLE_POLICY_ENGINE", "false").lower() == "true"
ENABLE_EVENT_MONITORING = os.getenv("ENABLE_EVENT_MONITORING", "false").lower() == "true"
ENABLE_ENV_CORRELATION = os.getenv("ENABLE_ENV_CORRELATION", "false").lower() == "true"
