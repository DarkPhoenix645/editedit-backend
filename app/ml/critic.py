from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger("forensiq.ml.critic")


class CriticEngine:
    def validate(self, generated_text: str, known_facts: list[dict]) -> dict[str, Any]:
        known_entities: set[str] = set()
        for fact in known_facts:
            for key in ("user_id", "source_ip", "dest_ip", "resource", "action", "event_id"):
                val = fact.get(key)
                if val:
                    known_entities.add(str(val).lower())

        extracted: set[str] = set()
        extracted.update(m.lower() for m in re.findall(r"'([^']+)'", generated_text))
        extracted.update(m.lower() for m in re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", generated_text))
        extracted.update(m.lower() for m in re.findall(r"[A-Z][A-Za-z0-9_-]{3,}", generated_text))

        unknown = extracted - known_entities
        stopwords = {"based", "user", "performed", "unknown", "matching", "events", "more", "trust", "none"}
        unknown = {u for u in unknown if u not in stopwords and len(u) > 2}

        is_valid = len(unknown) == 0
        if not is_valid:
            logger.warning("Critic flagged %d unknown entities: %s", len(unknown), unknown)

        return {
            "valid": is_valid,
            "unknown_entities": list(unknown),
            "known_entity_count": len(known_entities),
            "extracted_entity_count": len(extracted),
            "message": "Output validated" if is_valid else f"Rejected: {len(unknown)} unknown entities detected",
        }
