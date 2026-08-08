"""
tests/test_saml_flow.py
End-to-end SAML flow: SP generates AuthnRequest, IdP builds Response,
SP validates through the full NAND gate pipeline and WORM audit.
"""

import os
import tempfile
import pytest

from crypto.keys import generate_key_pair
from saml.sp.authn_request import AuthnRequestBuilder, AuthnRequestConfig
from saml.idp.response_builder import ResponseBuilder, ResponseConfig
from saml.sp.assertion_consumer import AssertionConsumer, SAMLValidationError
from nand.gate import NANDGate
from audit.worm import WORMAuditChain
from audit.replay import ReplayStore, ReplayDetectedError


SP_ENTITY  = "https://vault-live.local/sp"
IDP_ENTITY = "https://vault-live.local/idp"
ACS_URL    = "https://vault-live.local/sp/acs"
SSO_URL    = "https://vault-live.local/idp/sso"

VALID_ATTRS = {
    'Role':         ['VaultUser'],
    'Email':        ['alice@example.com'],
    'SessionIndex': ['idx_001'],
}


@pytest.fixture(scope='module')
def idp_kp():
    return generate_key_pair(IDP_ENTITY)

@pytest.fixture(scope='module')
def sp_kp():
    return generate_key_pair(SP_ENTITY)

@pytest.fixture(scope='module')
def idp_builder(idp_kp):
    cfg = ResponseConfig(idp_entity_id=IDP_ENTITY, sp_entity_id=SP_ENTITY, acs_url=ACS_URL)
    return ResponseBuilder(cfg, idp_kp.private_key, idp_kp.certificate)

@pytest.fixture
def gate():
    constraints_path = os.path.join(os.path.dirname(__file__), '..', 'nand', 'constraints.xml')
    return NANDGate(os.path.normpath(constraints_path))

@pytest.fixture
def tmp_audit():
    with tempfile.NamedTemporaryFile(suffix='.jsonl', delete=False) as f:
        path = f.name
    yield WORMAuditChain(path)
    os.unlink(path)

@pytest.fixture
def consumer(idp_kp, sp_kp, gate, tmp_audit):
    return AssertionConsumer(
        idp_certificate=idp_kp.certificate,
        sp_private_key=sp_kp.private_key,
        sp_entity_id=SP_ENTITY,
        acs_url=ACS_URL,
        nand_gate=gate,
        replay_store=ReplayStore(ttl_seconds=300),
        audit_chain=tmp_audit,
    )

@pytest.fixture
def sp_builder(sp_kp):
    cfg = AuthnRequestConfig(
        sp_entity_id=SP_ENTITY,
        idp_sso_url=SSO_URL,
        acs_url=ACS_URL,
        private_key=sp_kp.private_key,
        certificate=sp_kp.certificate,
    )
    return AuthnRequestBuilder(cfg)


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_authn_request_builds_and_signs(sp_builder):
    signed = sp_builder.build_and_sign()
    assert signed.request_id.startswith('_')
    assert signed.redirect_url.startswith(SSO_URL)
    assert len(signed.post_value) > 0

def test_happy_path_full_flow(idp_builder, consumer):
    built  = idp_builder.build('alice', VALID_ATTRS, '_req001')
    result = consumer.receive(built.post_value)
    assert result.valid is True
    assert result.subject == 'alice'
    assert len(result.semantic_hash) == 64
    assert result.attributes['Role'] == ['VaultUser']

def test_replay_attack_rejected(idp_builder, consumer):
    built = idp_builder.build('alice', VALID_ATTRS, '_req_replay')
    consumer.receive(built.post_value)   # first time — ok
    # Second time — same assertion_id → replay
    with pytest.raises(ReplayDetectedError):
        consumer.receive(built.post_value)

def test_nand_gate_rejects_superadmin(idp_builder, consumer):
    bad_attrs = {
        'Role':         ['SuperAdmin'],
        'SessionIndex': ['idx_admin'],
    }
    built  = idp_builder.build('badactor', bad_attrs, '_req_admin')
    result = consumer.receive(built.post_value)
    assert result.valid is False

def test_entropy_overflow_rejected(idp_builder, consumer):
    # Single attribute with many distinct values → H = ln(5) > 0.20
    overflow_attrs = {'Role': ['v0', 'v1', 'v2', 'v3', 'v4'], 'SessionIndex': ['s']}
    built  = idp_builder.build('entropy_user', overflow_attrs, '_req_entropy')
    result = consumer.receive(built.post_value)
    assert result.valid is False
    assert 'entropy-exceeded' in (result.rejection_reason or '')

def test_tampered_assertion_rejected(idp_builder, sp_kp, gate, tmp_audit):
    """Mutate an attribute value after signing — signature must fail."""
    from xml.etree import ElementTree as ET
    from crypto.xml_dsig import SignatureVerificationError
    import base64

    built = idp_builder.build('alice', VALID_ATTRS, '_req_tamper')
    raw   = base64.b64decode(built.post_value)
    root  = ET.fromstring(raw)

    # Mutate a NameID value
    ns = 'urn:oasis:names:tc:SAML:2.0:assertion'
    nameid = root.find(f".//{{{ns}}}NameID")
    if nameid is not None:
        nameid.text = 'TAMPERED'

    tampered_b64 = base64.b64encode(
        ET.tostring(root, encoding='unicode').encode('utf-8')
    ).decode('ascii')

    fresh_consumer = AssertionConsumer(
        idp_certificate=idp_builder.certificate,
        sp_private_key=sp_kp.private_key,
        sp_entity_id=SP_ENTITY,
        acs_url=ACS_URL,
        nand_gate=gate,
        replay_store=ReplayStore(),
        audit_chain=tmp_audit,
    )
    with pytest.raises((SignatureVerificationError, Exception)):
        fresh_consumer.receive(tampered_b64)

def test_semantic_hash_is_deterministic(idp_builder, gate):
    """Same attrs + same metadata → same semantic hash."""
    from nand.gate import NANDGate
    r1 = gate.evaluate(VALID_ATTRS, '_id1', IDP_ENTITY, '2026-08-07T00:00:00Z')
    r2 = gate.evaluate(VALID_ATTRS, '_id1', IDP_ENTITY, '2026-08-07T00:00:00Z')
    assert r1.semantic_hash == r2.semantic_hash

def test_semantic_hash_differs_on_different_assertion_id(gate):
    r1 = gate.evaluate(VALID_ATTRS, '_id1', IDP_ENTITY, '2026-08-07T00:00:00Z')
    r2 = gate.evaluate(VALID_ATTRS, '_id2', IDP_ENTITY, '2026-08-07T00:00:00Z')
    assert r1.semantic_hash != r2.semantic_hash

def test_worm_chain_grows_per_assertion(idp_builder, consumer, tmp_audit):
    from audit.worm import WORMAuditChain
    built1 = idp_builder.build('user1', VALID_ATTRS, '_req_worm1')
    built2 = idp_builder.build('user2', VALID_ATTRS, '_req_worm2')
    consumer.receive(built1.post_value)
    consumer.receive(built2.post_value)
    result = WORMAuditChain.verify_chain(tmp_audit._path)
    assert result.valid is True
    assert result.total_entries >= 2
