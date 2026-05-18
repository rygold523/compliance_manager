from datetime import datetime, timezone
from typing import Dict, Any
from app.continuous_compliance.services.hash_utils import sha256_text


class RegulatoryCollector:
    source_name = "undefined"
    document_type = "undefined"

    def fetch(self) -> str:
        raise NotImplementedError

    def normalize(self, raw_content: str) -> Dict[str, Any]:
        return {
            "source_name": self.source_name,
            "document_type": self.document_type,
            "content": raw_content.strip(),
        }

    def collect(self) -> Dict[str, Any]:
        raw_content = self.fetch()
        normalized = self.normalize(raw_content)
        content_hash = sha256_text(raw_content)

        return {
            "collector": self.__class__.__name__,
            "source_name": self.source_name,
            "document_type": self.document_type,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "content_hash": content_hash,
            "normalized_content": normalized,
            "raw_content": raw_content,
            "evidence_scope": "regulatory",
            "coverage_basis": "governance_record",
            "authoritative_source": True,
        }
