from __future__ import annotations

from types import SimpleNamespace

from app.services.sealing_service import seal_event_batch


class _FakeQuery:
    def __init__(self, existing):
        self._existing = existing

    def filter(self, *args, **kwargs):  # noqa: ANN002, ANN003
        return self

    def order_by(self, *args, **kwargs):  # noqa: ANN002, ANN003
        return self

    def first(self):
        return self._existing


class _FakeDB:
    def __init__(self, existing):
        self._existing = existing

    def query(self, *args, **kwargs):  # noqa: ANN002, ANN003
        return _FakeQuery(self._existing)


def test_seal_block_idempotent_returns_existing_block() -> None:
    existing = SimpleNamespace(
        id="existing-id",
        storage_uri="s3://forensiq-cold-dev/blocks/existing.raw",
    )
    db = _FakeDB(existing)
    events = [
        {"@timestamp": "2026-03-24T10:00:00Z", "message": "a", "host": {"name": "n1"}},
        {"@timestamp": "2026-03-24T10:00:01Z", "message": "b", "host": {"name": "n1"}},
    ]
    result = seal_event_batch(db=db, source_id="source-1", events=events)
    assert result.block.id == "existing-id"
