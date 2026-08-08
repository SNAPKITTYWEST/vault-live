"""
audit/worm.py
Append-only WORM audit chain. Each record is chained via SHA-256.
The Semantic Hash from the NAND gate is the immutable identity anchor.
"""

import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AuditRecord:
    timestamp:       str
    semantic_hash:   str
    assertion_id:    str
    issuer:          str
    subject:         str
    gate_result:     bool
    entropy:         float
    attributes_hash: str   # SHA-256 of sorted attr JSON — no raw values
    event:           str   # ASSERTION_ACCEPTED | ASSERTION_REJECTED | ...

    def canonical_json(self) -> str:
        d = {
            'assertion_id':    self.assertion_id,
            'attributes_hash': self.attributes_hash,
            'entropy':         round(self.entropy, 6),
            'event':           self.event,
            'gate_result':     self.gate_result,
            'issuer':          self.issuer,
            'semantic_hash':   self.semantic_hash,
            'subject':         self.subject,
            'timestamp':       self.timestamp,
        }
        return json.dumps(d, sort_keys=True, separators=(',', ':'))


@dataclass
class ChainEntry:
    sequence:   int
    prev_hash:  str
    entry_hash: str
    record:     AuditRecord


@dataclass
class ChainVerifyResult:
    valid:         bool
    broken_at:     Optional[int]
    total_entries: int
    error:         Optional[str] = None


class WORMAuditChain:
    def __init__(self, path: str):
        self._path = path
        self._sequence = 0
        self._prev_hash = '0' * 64

        # Load last entry to restore chain state
        try:
            with open(path, 'r', encoding='utf-8') as f:
                lines = [l.strip() for l in f if l.strip()]
            if lines:
                last = json.loads(lines[-1])
                self._prev_hash = last['entry_hash']
                self._sequence  = last['sequence'] + 1
        except FileNotFoundError:
            pass

    def append(self, record: AuditRecord) -> ChainEntry:
        entry_hash = hashlib.sha256(
            (self._prev_hash + record.canonical_json()).encode('utf-8')
        ).hexdigest()

        entry = ChainEntry(
            sequence=self._sequence,
            prev_hash=self._prev_hash,
            entry_hash=entry_hash,
            record=record,
        )

        line = json.dumps({
            'sequence':   entry.sequence,
            'prev_hash':  entry.prev_hash,
            'entry_hash': entry.entry_hash,
            'record':     json.loads(record.canonical_json()),
        }, sort_keys=True, separators=(',', ':'))

        with open(self._path, 'a', encoding='utf-8') as f:
            f.write(line + '\n')

        self._prev_hash  = entry_hash
        self._sequence  += 1
        return entry

    @staticmethod
    def verify_chain(path: str) -> ChainVerifyResult:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                lines = [l.strip() for l in f if l.strip()]
        except FileNotFoundError:
            return ChainVerifyResult(valid=True, broken_at=None, total_entries=0)

        prev_hash = '0' * 64
        for i, line in enumerate(lines):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as e:
                return ChainVerifyResult(valid=False, broken_at=i, total_entries=len(lines),
                                         error=f"JSON parse error: {e}")

            if entry.get('prev_hash') != prev_hash:
                return ChainVerifyResult(valid=False, broken_at=i, total_entries=len(lines),
                                         error="prev_hash mismatch")

            record_json = json.dumps(entry['record'], sort_keys=True, separators=(',', ':'))
            expected_hash = hashlib.sha256(
                (prev_hash + record_json).encode('utf-8')
            ).hexdigest()

            if entry.get('entry_hash') != expected_hash:
                return ChainVerifyResult(valid=False, broken_at=i, total_entries=len(lines),
                                         error="entry_hash mismatch")

            prev_hash = entry['entry_hash']

        return ChainVerifyResult(valid=True, broken_at=None, total_entries=len(lines))


def attributes_hash(attrs: dict) -> str:
    """SHA-256 of sorted attribute JSON. No raw values stored in audit records."""
    sorted_attrs = {k: sorted(v) for k, v in sorted(attrs.items())}
    return hashlib.sha256(
        json.dumps(sorted_attrs, sort_keys=True, separators=(',', ':')).encode('utf-8')
    ).hexdigest()
