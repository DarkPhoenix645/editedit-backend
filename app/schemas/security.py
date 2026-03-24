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
    merkle_root: bytes
    chain_hash: bytes
    tsa_token: bytes
    authoritative_time: datetime
    rsa_signature: bytes
    signing_key_id: str
    storage_uri: str
    logstash_config_version: str
    model_config = ConfigDict(from_attributes=True)

class HotColdTrace(BaseModel):
    id: int
    event_fingerprint: str
    elastic_event_id: Optional[str] = None
    cold_offset: int
    storage_uri: str
    block_id: UUID
    model_config = ConfigDict(from_attributes=True)