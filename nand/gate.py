"""
nand/gate.py
NAND-gated assertion validation pipeline.
Loads constraints.xml, evaluates attributes through a boolean constraint tree,
enforces H <= 0.20 nat entropy trust window, returns (valid, semantic_hash).
"""

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from typing import Optional
from xml.etree import ElementTree as ET

VL_NS = "urn:vault-live:nand:1.0"
_VL   = "{%s}" % VL_NS

ENTROPY_CAP = 0.20


class ConstraintParseError(Exception):
    pass


@dataclass
class ConstraintLeaf:
    id:             str
    attribute_name: str
    predicate:      str
    value:          str = ""


@dataclass
class ConstraintTree:
    id:        str
    gate_type: str   # NAND AND OR NOR NOT
    children:  list  # list[ConstraintTree | ConstraintLeaf]


@dataclass
class GateResult:
    valid:            bool
    semantic_hash:    str
    entropy:          float
    tree_result:      bool
    rejection_reason: Optional[str] = None


class NANDGate:
    def __init__(self, constraints_path: str = "nand/constraints.xml"):
        self._tree = self._load_constraints(constraints_path)
        self._entropy_cap = ENTROPY_CAP

    # ── Public API ────────────────────────────────────────────────────────────

    def evaluate(
        self,
        attrs:           dict,
        assertion_id:    str = "",
        issuer:          str = "",
        issue_instant:   str = "",
    ) -> GateResult:
        tree_result, rejection_reason = self._evaluate_tree(attrs, self._tree)
        entropy = self._compute_entropy(attrs)

        valid = tree_result
        if entropy > self._entropy_cap:
            valid = False
            rejection_reason = (rejection_reason or "") + (
                f" entropy-exceeded({entropy:.6f}>{self._entropy_cap})"
            )

        semantic_hash = self._compute_semantic_hash(
            attrs, assertion_id, issuer, issue_instant, tree_result, entropy
        )

        return GateResult(
            valid=valid,
            semantic_hash=semantic_hash,
            entropy=entropy,
            tree_result=tree_result,
            rejection_reason=rejection_reason or None,
        )

    # ── Tree evaluation ───────────────────────────────────────────────────────

    def _evaluate_tree(self, attrs: dict, node) -> tuple[bool, Optional[str]]:
        if isinstance(node, ConstraintLeaf):
            result = self._evaluate_leaf(attrs, node)
            reason = None if result else f"leaf-failed:{node.id}"
            return result, reason

        # Compound gate
        child_results = []
        child_reasons = []
        for child in node.children:
            r, reason = self._evaluate_tree(attrs, child)
            child_results.append(r)
            if reason:
                child_reasons.append(reason)

        gate = node.gate_type.upper()

        if gate == 'AND':
            result = all(child_results)
        elif gate == 'OR':
            result = any(child_results)
        elif gate == 'NAND':
            result = not all(child_results)
        elif gate == 'NOR':
            result = not any(child_results)
        elif gate == 'NOT':
            result = not child_results[0] if child_results else True
        else:
            raise ConstraintParseError(f"Unknown gate type: {gate}")

        reason = f"gate-failed:{node.id}[{','.join(child_reasons)}]" if not result else None
        return result, reason

    def _evaluate_leaf(self, attrs: dict, leaf: ConstraintLeaf) -> bool:
        values = attrs.get(leaf.attribute_name, [])
        p = leaf.predicate.lower()

        if p == 'present':
            return len(values) > 0
        elif p == 'absent':
            return len(values) == 0
        elif p == 'eq':
            return leaf.value in values
        elif p == 'contains':
            return any(leaf.value in v for v in values)
        elif p == 'regex':
            return any(re.search(leaf.value, v) for v in values)
        elif p == 'bounded':
            # special: attribute count <= total distinct values <= some threshold
            total = sum(len(v) for v in attrs.values())
            return total <= 10
        else:
            raise ConstraintParseError(f"Unknown predicate: {leaf.predicate}")

    # ── Entropy ───────────────────────────────────────────────────────────────

    def _compute_entropy(self, attrs: dict) -> float:
        """
        Shannon entropy in nats over the distribution of values per attribute.
        Computed as the average per-attribute entropy, weighted by attribute count.
        An attribute with a single deterministic value contributes H=0.
        Multiple values for one attribute or repeated values across attributes
        increase entropy.
        This matches the 'trust window' constraint: near-deterministic sets pass.
        """
        from collections import Counter
        if not attrs:
            return 0.0
        total_entropy = 0.0
        total_values  = 0
        for values in attrs.values():
            if not values:
                continue
            n = len(values)
            total_values += n
            counts = Counter(values)
            for count in counts.values():
                p = count / n
                if p > 0:
                    total_entropy -= p * math.log(p)
        # Normalise by attribute count so adding more attributes doesn't auto-fail
        return total_entropy / len(attrs) if attrs else 0.0

    # ── Semantic hash ─────────────────────────────────────────────────────────

    def _compute_semantic_hash(
        self,
        attrs:         dict,
        assertion_id:  str,
        issuer:        str,
        issue_instant: str,
        tree_result:   bool,
        entropy:       float,
    ) -> str:
        sorted_attrs = {k: sorted(v) for k, v in sorted(attrs.items())}
        canonical_attrs = json.dumps(sorted_attrs, sort_keys=True, separators=(',', ':'))
        payload = '|'.join([
            assertion_id,
            issuer,
            issue_instant.strip(),
            str(int(tree_result)),
            f"{entropy:.6f}",
            canonical_attrs,
        ])
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()

    # ── Constraint XML parser ─────────────────────────────────────────────────

    def _load_constraints(self, path: str) -> ConstraintTree:
        tree = ET.parse(path)
        root = tree.getroot()
        trust_window = root.find(_VL + 'TrustWindow')
        if trust_window is None:
            raise ConstraintParseError("No vl:TrustWindow found in constraints.xml")

        # Find the root gate inside TrustWindow
        for child in trust_window:
            tag = child.tag.replace(_VL, '')
            if tag in ('NAND', 'AND', 'OR', 'NOR', 'NOT'):
                return self._parse_node(child)
        raise ConstraintParseError("No root gate found in vl:TrustWindow")

    def _parse_node(self, element: ET.Element):
        tag = element.tag.replace(_VL, '')
        node_id = element.get('id', tag)

        if tag == 'Leaf':
            predicate = element.get('predicate')
            if predicate is None:
                raise ConstraintParseError(f"Leaf missing predicate: {node_id}")
            if predicate not in ('present', 'absent', 'eq', 'contains', 'regex', 'bounded'):
                raise ConstraintParseError(f"Unknown predicate '{predicate}' in leaf {node_id}")
            return ConstraintLeaf(
                id=node_id,
                attribute_name=element.get('attribute', ''),
                predicate=predicate,
                value=element.get('value', ''),
            )

        if tag not in ('NAND', 'AND', 'OR', 'NOR', 'NOT'):
            raise ConstraintParseError(f"Unknown gate type: {tag}")

        children = [self._parse_node(child) for child in element]
        return ConstraintTree(id=node_id, gate_type=tag, children=children)
