"""
audit/replay.py
Replay protection: records seen assertion IDs, rejects duplicates within TTL.
"""

import json
from datetime import datetime, timezone
from typing import Optional


class ReplayDetectedError(Exception):
    def __init__(self, assertion_id: str, original_seen_at: str):
        self.assertion_id     = assertion_id
        self.original_seen_at = original_seen_at
        super().__init__(f"Replay detected: assertion {assertion_id} already seen at {original_seen_at}")


class MemoryBackend:
    def __init__(self):
        self._store: dict[str, tuple[datetime, str]] = {}  # id → (expiry, seen_at)

    def get(self, assertion_id: str) -> Optional[tuple]:
        return self._store.get(assertion_id)

    def put(self, assertion_id: str, expiry: datetime, seen_at: str) -> None:
        self._store[assertion_id] = (expiry, seen_at)

    def delete(self, assertion_id: str) -> None:
        self._store.pop(assertion_id, None)

    def all_ids(self) -> list[str]:
        return list(self._store.keys())


class FileBackend:
    def __init__(self, path: str):
        self._path = path
        self._mem  = MemoryBackend()
        self._load()

    def _load(self):
        try:
            with open(self._path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            for aid, (exp_str, seen_at) in data.items():
                expiry = datetime.fromisoformat(exp_str)
                self._mem.put(aid, expiry, seen_at)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def _flush(self):
        data = {}
        for aid in self._mem.all_ids():
            entry = self._mem.get(aid)
            if entry:
                expiry, seen_at = entry
                data[aid] = (expiry.isoformat(), seen_at)
        with open(self._path, 'w', encoding='utf-8') as f:
            json.dump(data, f)

    def get(self, assertion_id: str):
        return self._mem.get(assertion_id)

    def put(self, assertion_id: str, expiry: datetime, seen_at: str) -> None:
        self._mem.put(assertion_id, expiry, seen_at)
        self._flush()

    def delete(self, assertion_id: str) -> None:
        self._mem.delete(assertion_id)
        self._flush()

    def all_ids(self) -> list[str]:
        return self._mem.all_ids()


class ReplayStore:
    def __init__(self, ttl_seconds: int = 300, backend=None):
        self._ttl     = ttl_seconds
        self._backend = backend or MemoryBackend()

    def check_and_store(self, assertion_id: str, not_on_or_after: str) -> None:
        self._purge_expired()
        now = datetime.now(timezone.utc)

        existing = self._backend.get(assertion_id)
        if existing:
            expiry, seen_at = existing
            if expiry > now:
                raise ReplayDetectedError(assertion_id, seen_at)
            # Expired — remove stale entry
            self._backend.delete(assertion_id)

        # Parse expiry from assertion
        try:
            expiry = datetime.fromisoformat(not_on_or_after.replace('Z', '+00:00'))
        except ValueError:
            expiry = now.replace(tzinfo=timezone.utc)
            from datetime import timedelta
            expiry += timedelta(seconds=self._ttl)

        seen_at = now.isoformat()
        self._backend.put(assertion_id, expiry, seen_at)

    def is_seen(self, assertion_id: str) -> bool:
        entry = self._backend.get(assertion_id)
        if not entry:
            return False
        expiry, _ = entry
        return expiry > datetime.now(timezone.utc)

    def _purge_expired(self) -> int:
        now    = datetime.now(timezone.utc)
        stale  = [aid for aid in self._backend.all_ids()
                  if (entry := self._backend.get(aid)) and entry[0] <= now]
        for aid in stale:
            self._backend.delete(aid)
        return len(stale)
