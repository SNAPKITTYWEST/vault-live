# vault-live

SAML 2.0 SP/IdP with a NAND-gated assertion validation pipeline.

Every inbound SAML assertion passes through a boolean constraint tree before any attribute is trusted. The constraint tree is written in XML — the same language as SAML itself. The entropy of the attribute set is bounded at 0.20 nats. The Semantic Hash produced by the gate is the immutable anchor for the WORM audit chain.

**Stack:** Python + `cryptography` library. No lxml, no xmlsec, no external SAML library.  
**Tests:** 31 passing — `pytest tests/`

---

## How it works

```
IdP produces signed SAML Response
         │
         ▼  Base64 decode → XML parse
         │
         ▼  Signature verification (RSA-SHA256, enveloped)
         │  uses IdP signing certificate as verification root
         │
         ▼  Assertion validation
         │  Conditions: NotBefore / NotOnOrAfter clock check
         │  SubjectConfirmationData: Recipient + expiry
         │  Audience restriction: must match SP EntityID
         │
         ▼  Replay protection
         │  assertion ID stored with expiry; duplicate → ReplayDetectedError
         │
         ▼  NAND gate  ← constraints.xml is the program
         │  evaluates attribute set through boolean constraint tree
         │  computes Shannon entropy H(attr values) in nats
         │  enforces H <= 0.20
         │  produces Semantic Hash (SHA-256, deterministic)
         │
         ▼  WORM audit chain
            AuditRecord appended: semantic_hash, assertion_id, gate_result, H
            SHA-256 chain: entry_hash = SHA256(prev_hash + record_json)
            tamper any record → chain verification fails
```

---

## The NAND gate

The constraint program lives in `nand/constraints.xml`. It is XML evaluated against the assertion's attribute map.

```
NAND(branch1, branch2) = NOT(branch1 AND branch2)

branch1 (session-check):  Role present AND SessionIndex present
branch2 (privilege-escalation):  Role == "SuperAdmin"

VaultUser:  NAND(True, False) = True   → TRUSTED
SuperAdmin: NAND(True, True)  = False  → BLOCKED
```

The security property: an attacker with maximum privileges satisfies all branches simultaneously, causing NAND to output False. A legitimate user fails at least one "attacker" branch, keeping NAND True.

Entropy constraint: an assertion with multiple distinct values per attribute raises H above 0.20 nats and is rejected regardless of the tree result.

The Semantic Hash binds the assertion identity to the audit record:

```python
semantic_hash = SHA256(
    assertion_id + "|" + issuer + "|" + issue_instant + "|"
    + str(int(tree_result)) + "|" + f"{entropy:.6f}" + "|"
    + json.dumps(sorted_attrs, sort_keys=True, separators=(',',':'))
)
```

---

## Modules

```
vault-live/
├── crypto/
│   ├── keys.py         RSA key generation, self-signed X.509, PEM load/save
│   ├── xml_dsig.py     XML-DSig: RSA-SHA256 sign/verify, Exclusive C14N
│   └── xml_encrypt.py  XML Encryption: AES-256-GCM payload, RSA-OAEP key wrap
│
├── nand/
│   ├── constraints.xml  Constraint DSL (vl: namespace) — the program IS XML
│   └── gate.py          NANDGate: tree eval, entropy, semantic hash
│
├── saml/
│   ├── metadata.xml     SP metadata (EntityID, ACS, signing cert)
│   ├── idp_metadata.xml IdP metadata (EntityID, SSO endpoint, signing cert)
│   ├── sp/
│   │   ├── authn_request.py    AuthnRequest builder + HTTP-Redirect encoding
│   │   └── assertion_consumer.py  ACS: full validation chain + NAND gate
│   └── idp/
│       └── response_builder.py  Response + signed Assertion builder
│
├── audit/
│   ├── worm.py    Append-only SHA-256 chain, verify_chain(), AuditRecord
│   └── replay.py  ReplayStore: seen assertion IDs + expiry, file backend
│
└── tests/
    ├── test_saml_flow.py   End-to-end: authn request, full flow, replay, tamper
    ├── test_nand_gate.py   Gate logic, entropy, semantic hash, constraint DSL
    └── test_audit.py       WORM chain, tamper detection, replay store
```

---

## Running

```bash
pip install cryptography pytest
pytest tests/ -v
```

---

## Why XML as the constraint language

SAML is XML. The assertions being validated are XML. The SP/IdP metadata is XML. Writing the constraint program in the same language (`vl:` namespace, `nand/constraints.xml`) means the trust policy is readable by the same tooling that reads the protocol — XPath queries, XML validators, schema checkers, diff tools. GitHub's language detector counts it as XML, which is accurate: the constraint tree is the program.

---

Built by Ahmad Ali Parr × SnapKitty.
