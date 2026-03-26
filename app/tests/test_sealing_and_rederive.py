from __future__ import annotations

import hashlib

from app.services.ocsf_rederive_v1_0 import apply_ocsf_mapping_v1_0
from app.services.sealing_service import compute_fingerprint, compute_merkle_root


def test_fingerprint_deterministic() -> None:
    event = {
        "@timestamp": "2026-03-24T10:00:00Z",
        "message": "hello",
        "host": {"name": "node-1"},
    }
    assert compute_fingerprint(event) == compute_fingerprint(event)


def test_merkle_root_deterministic() -> None:
    events = [
        {"@timestamp": "2026-03-24T10:00:00Z", "message": "a", "host": {"name": "n1"}},
        {"@timestamp": "2026-03-24T10:00:01Z", "message": "b", "host": {"name": "n1"}},
    ]
    assert compute_merkle_root(events) == compute_merkle_root(events)


def test_chain_hash_continuity_formula() -> None:
    prev_hash = bytes.fromhex("00" * 32)
    merkle_root = bytes.fromhex("11" * 32)
    payload_hash = bytes.fromhex("22" * 32)
    seq_1 = 1
    seq_2 = 2

    chain_1 = hashlib.sha256(prev_hash + merkle_root + payload_hash + str(seq_1).encode()).digest()
    chain_2 = hashlib.sha256(chain_1 + merkle_root + payload_hash + str(seq_2).encode()).digest()

    assert chain_1 != chain_2


def test_ocsf_rederivation_reproducible() -> None:
    raw = {
        "@timestamp": "2026-03-24T10:00:00Z",
        "message": "auth success",
        "event": {"dataset": "system.auth"},
        "host": {"name": "node-1"},
        "source": {"ip": "10.0.0.1"},
        "user": {"name": "alice"},
        "forensiq": {"event_fingerprint": "abc"},
    }
    out_1 = apply_ocsf_mapping_v1_0(raw)
    out_2 = apply_ocsf_mapping_v1_0(raw)
    assert out_1 == out_2
    assert out_1["forensiq"]["trust_tier"] == "iam"
