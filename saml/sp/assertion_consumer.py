"""
saml/sp/assertion_consumer.py
ACS endpoint: receive Response, validate full chain, run NAND gate, emit audit.
"""

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional
from xml.etree import ElementTree as ET

from crypto.xml_dsig import verify_signature, SignatureVerificationError
from nand.gate import NANDGate, GateResult
from audit.worm import WORMAuditChain, AuditRecord, attributes_hash
from audit.replay import ReplayStore, ReplayDetectedError

SAML_NS  = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
XENC_NS  = "http://www.w3.org/2001/04/xmlenc#"
_SA  = "{%s}" % SAML_NS
_SAP = "{%s}" % SAMLP_NS
_XE  = "{%s}" % XENC_NS

STATUS_SUCCESS   = "urn:oasis:names:tc:SAML:2.0:status:Success"
CLOCK_SKEW_SECS  = 300


class SAMLParseError(Exception):    pass
class SAMLValidationError(Exception): pass


@dataclass
class ConsumeResult:
    valid:         bool
    subject:       str
    attributes:    dict
    semantic_hash: str
    assertion_id:  str
    rejection_reason: Optional[str] = None


class AssertionConsumer:
    def __init__(
        self,
        idp_certificate,
        sp_private_key,
        sp_entity_id:  str,
        acs_url:       str,
        nand_gate:     NANDGate,
        replay_store:  ReplayStore,
        audit_chain:   WORMAuditChain,
        clock_skew:    int = CLOCK_SKEW_SECS,
    ):
        self.idp_cert     = idp_certificate
        self.sp_key       = sp_private_key
        self.sp_entity_id = sp_entity_id
        self.acs_url      = acs_url
        self.gate         = nand_gate
        self.replay       = replay_store
        self.audit        = audit_chain
        self.clock_skew   = clock_skew

    def receive(self, saml_response_b64: str) -> ConsumeResult:
        raw_xml = base64.b64decode(saml_response_b64)
        root    = self._parse_response(raw_xml)

        self._validate_response(root)
        assertion = self._extract_assertion(root)
        self._validate_assertion(assertion)

        subject = self._extract_subject(assertion)
        attrs   = self._extract_attributes(assertion)
        assertion_id   = assertion.get('ID', '_unknown')
        issuer_el      = assertion.find(_SA + 'Issuer')
        issuer         = issuer_el.text.strip() if issuer_el is not None else ''
        issue_instant  = assertion.get('IssueInstant', '')

        # Replay check — use SubjectConfirmationData.NotOnOrAfter
        not_on_or_after = self._get_not_on_or_after(assertion)
        self.replay.check_and_store(assertion_id, not_on_or_after)

        gate_result: GateResult = self.gate.evaluate(
            attrs, assertion_id, issuer, issue_instant
        )

        event = 'ASSERTION_ACCEPTED' if gate_result.valid else 'ASSERTION_REJECTED'
        record = AuditRecord(
            timestamp=datetime.now(timezone.utc).isoformat(),
            semantic_hash=gate_result.semantic_hash,
            assertion_id=assertion_id,
            issuer=issuer,
            subject=subject,
            gate_result=gate_result.valid,
            entropy=gate_result.entropy,
            attributes_hash=attributes_hash(attrs),
            event=event,
        )
        self.audit.append(record)

        return ConsumeResult(
            valid=gate_result.valid,
            subject=subject,
            attributes=attrs,
            semantic_hash=gate_result.semantic_hash,
            assertion_id=assertion_id,
            rejection_reason=gate_result.rejection_reason,
        )

    # ── Internal validation ───────────────────────────────────────────────────

    def _parse_response(self, raw_xml: bytes) -> ET.Element:
        try:
            return ET.fromstring(raw_xml)
        except ET.ParseError as e:
            raise SAMLParseError(f"XML parse error: {e}")

    def _validate_response(self, root: ET.Element) -> None:
        # Status
        status_code = root.find(f".//{_SAP}StatusCode")
        if status_code is None or status_code.get('Value') != STATUS_SUCCESS:
            raise SAMLValidationError("Response status is not Success")

        # Destination
        dest = root.get('Destination', '')
        if dest and dest != self.acs_url:
            raise SAMLValidationError(f"Destination mismatch: {dest} != {self.acs_url}")

        # IssueInstant clock skew
        issue_instant = root.get('IssueInstant', '')
        if issue_instant:
            self._check_clock_skew(issue_instant)

    def _extract_assertion(self, root: ET.Element) -> ET.Element:
        # Try encrypted first
        enc = root.find(f".//{_SA}EncryptedAssertion")
        if enc is not None:
            from crypto.xml_encrypt import decrypt_assertion
            return decrypt_assertion(enc, self.sp_key)

        assertion = root.find(_SA + 'Assertion')
        if assertion is None:
            assertion = root.find(f".//{_SA}Assertion")
        if assertion is None:
            raise SAMLValidationError("No saml:Assertion found in Response")
        return assertion

    def _validate_assertion(self, assertion: ET.Element) -> None:
        now = datetime.now(timezone.utc)
        skew = timedelta(seconds=self.clock_skew)

        # Conditions timing
        conditions = assertion.find(_SA + 'Conditions')
        if conditions is not None:
            not_before_str = conditions.get('NotBefore', '')
            not_after_str  = conditions.get('NotOnOrAfter', '')
            if not_before_str:
                nb = self._parse_saml_datetime(not_before_str)
                if now < nb - skew:
                    raise SAMLValidationError(f"Assertion not yet valid: NotBefore={not_before_str}")
            if not_after_str:
                na = self._parse_saml_datetime(not_after_str)
                if now > na + skew:
                    raise SAMLValidationError(f"Assertion expired: NotOnOrAfter={not_after_str}")

            # Audience
            audience = assertion.findtext(f".//{_SA}Audience", '')
            if audience and audience.strip() != self.sp_entity_id:
                raise SAMLValidationError(f"Audience mismatch: {audience}")

        # Signature
        verify_signature(assertion, self.idp_cert)

    def _extract_subject(self, assertion: ET.Element) -> str:
        nameid = assertion.find(f".//{_SA}NameID")
        return nameid.text.strip() if nameid is not None and nameid.text else ''

    def _extract_attributes(self, assertion: ET.Element) -> dict:
        attrs = {}
        for attr in assertion.findall(f".//{_SA}Attribute"):
            name   = attr.get('Name', '')
            values = [
                v.text.strip() if v.text else ''
                for v in attr.findall(_SA + 'AttributeValue')
            ]
            if name:
                attrs[name] = values
        return attrs

    def _get_not_on_or_after(self, assertion: ET.Element) -> str:
        scd = assertion.find(f".//{_SA}SubjectConfirmationData")
        if scd is not None:
            return scd.get('NotOnOrAfter', '')
        conditions = assertion.find(_SA + 'Conditions')
        if conditions is not None:
            return conditions.get('NotOnOrAfter', '')
        return ''

    def _check_clock_skew(self, issue_instant: str) -> None:
        now  = datetime.now(timezone.utc)
        skew = timedelta(seconds=self.clock_skew)
        try:
            dt = self._parse_saml_datetime(issue_instant)
        except ValueError:
            return
        if dt > now + skew:
            raise SAMLValidationError(f"IssueInstant too far in future: {issue_instant}")
        if dt < now - timedelta(hours=8):
            raise SAMLValidationError(f"IssueInstant too old: {issue_instant}")

    @staticmethod
    def _parse_saml_datetime(s: str) -> datetime:
        s = s.replace('Z', '+00:00')
        return datetime.fromisoformat(s)
