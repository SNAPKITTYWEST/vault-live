"""
tests/test_audit.py
WORM chain integrity, replay store, semantic hash as chain anchor.
"""

import json
import os
import tempfile
import pytest
from datetime import datetime, timedelta, timezone

from audit.worm import WORMAuditChain, AuditRecord, attributes_hash
from audit.replay import ReplayStore, ReplayDetectedError, FileBackend


def _record(event='ASSERTION_ACCEPTED', seq=0) -> AuditRecord:
    return AuditRecord(
        timestamp='2026-08-07T00:00:00+00:00',
        semantic_hash='a' * 64,
        assertion_id=f'_id_{seq}',
        issuer='https://vault-live.local/idp',
        subject='alice',
        gate_result=True,
        entropy=0.0,
        attributes_hash='b' * 64,
        event=event,
    )


@pytest.fixture
def tmp_worm():
    with tempfile.NamedTemporaryFile(suffix='.jsonl', delete=False) as f:
        path = f.name
    chain = WORMAuditChain(path)
    yield chain, path
    os.unlink(path)


# ── WORM chain tests ──────────────────────────────────────────────────────────

def test_chain_grows_sequentially(tmp_worm):
    chain, path = tmp_worm
    for i in range(5):
        chain.append(_record(seq=i))
    result = WORMAuditChain.verify_chain(path)
    assert result.valid is True
    assert result.total_entries == 5
    assert result.broken_at is None

def test_chain_verify_empty_file():
    with tempfile.NamedTemporaryFile(suffix='.jsonl', delete=False) as f:
        path = f.name
    result = WORMAuditChain.verify_chain(path)
    assert result.valid is True
    assert result.total_entries == 0
    os.unlink(path)

def test_chain_tamper_detected(tmp_worm):
    chain, path = tmp_worm
    for i in range(5):
        chain.append(_record(seq=i))

    # Tamper the third record
    with open(path, 'r') as f:
        lines = f.readlines()
    entry = json.loads(lines[2])
    entry['record']['event'] = 'TAMPERED'
    lines[2] = json.dumps(entry) + '\n'
    with open(path, 'w') as f:
        f.writelines(lines)

    result = WORMAuditChain.verify_chain(path)
    assert result.valid is False
    assert result.broken_at == 2

def test_semantic_hash_is_chain_anchor(tmp_worm):
    """Two records with the same semantic_hash get distinct chain hashes."""
    chain, path = tmp_worm
    r1 = _record(seq=0)
    r2 = _record(seq=1)
    r2.semantic_hash = r1.semantic_hash  # same semantic hash

    e1 = chain.append(r1)
    e2 = chain.append(r2)

    assert e1.entry_hash != e2.entry_hash  # chain hashes differ
    assert e1.record.semantic_hash == e2.record.semantic_hash

def test_attributes_hash_not_plaintext():
    """attributes_hash output must not contain any raw value."""
    attrs = {'Role': ['VaultUser'], 'Email': ['alice@example.com']}
    h = attributes_hash(attrs)
    assert 'VaultUser' not in h
    assert 'alice@example.com' not in h
    assert len(h) == 64


# ── Replay store tests ────────────────────────────────────────────────────────

def _future(seconds: int = 300) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()

def _past(seconds: int = 10) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()

def test_replay_store_blocks_duplicate():
    store = ReplayStore(ttl_seconds=300)
    store.check_and_store('_id1', _future())
    with pytest.raises(ReplayDetectedError) as exc_info:
        store.check_and_store('_id1', _future())
    assert exc_info.value.assertion_id == '_id1'

def test_replay_store_allows_different_ids():
    store = ReplayStore()
    store.check_and_store('_id_a', _future())
    store.check_and_store('_id_b', _future())  # different ID — should not raise

def test_replay_store_allows_after_expiry():
    store = ReplayStore(ttl_seconds=300)
    store.check_and_store('_id_exp', _past(10))  # already expired
    # Should be treated as new since it's expired
    store.check_and_store('_id_exp', _future())  # re-admissible

def test_purge_expired_clears_stale():
    store = ReplayStore(ttl_seconds=300)
    for i in range(10):
        store._backend.put(f'_stale_{i}', datetime.now(timezone.utc) - timedelta(seconds=1), 'seen')
    purged = store._purge_expired()
    assert purged == 10
    assert all(not store.is_seen(f'_stale_{i}') for i in range(10))

def test_file_backend_survives_reload():
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
        path = f.name
    try:
        store1 = ReplayStore(backend=FileBackend(path))
        store1.check_and_store('_persist_id', _future())

        store2 = ReplayStore(backend=FileBackend(path))
        with pytest.raises(ReplayDetectedError):
            store2.check_and_store('_persist_id', _future())
    finally:
        os.unlink(path)
