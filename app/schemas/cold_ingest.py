from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class ColdIngestResponse(BaseModel):
    source_id: UUID
    block_id: UUID
    sequence_number: int
    stored_events: int
    authoritative_time: datetime
