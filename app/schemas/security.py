from pydantic import BaseModel, ConfigDict
from uuid import UUID
from datetime import datetime
from typing import Optional

class SealedBlock(BaseModel):
    id: UUID
    source_id: UUID
    sequence_number: int
    window_start: datetime
    window_end: datetime
    log_count: int
    payload_hash: bytes
    chain_hash: bytes
    tsa_token: Optional[bytes] = None
    authoritative_time: datetime
    rsa_signature: bytes
    signing_key_id: str
    storage_uri: str
    model_config = ConfigDict(from_attributes=True)

class HotColdTrace(BaseModel):
    id: int
    elastic_event_id: str
    block_id: UUID
    model_config = ConfigDict(from_attributes=True)