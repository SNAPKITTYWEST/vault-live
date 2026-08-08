"""
saml/idp/response_builder.py
SAML Response + Assertion builder with XML-DSig.
"""

import base64
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from xml.etree import ElementTree as ET

from crypto.xml_dsig import sign_element

SAML_NS  = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
XSI_NS   = "http://www.w3.org/2001/XMLSchema-instance"
XS_NS    = "http://www.w3.org/2001/XMLSchema"
_SA  = "{%s}" % SAML_NS
_SAP = "{%s}" % SAMLP_NS
_XSI = "{%s}" % XSI_NS

STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
BEARER_METHOD  = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
TRANSIENT_FMT  = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
AUTHN_PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"


@dataclass
class ResponseConfig:
    idp_entity_id:    str
    sp_entity_id:     str
    acs_url:          str
    session_ttl_seconds: int = 300


@dataclass
class BuiltResponse:
    element:     ET.Element
    response_id: str
    assertion_id: str
    post_value:  str


class ResponseBuilder:
    def __init__(self, config: ResponseConfig, private_key, certificate):
        self.config      = config
        self.private_key = private_key
        self.certificate = certificate

    def build(
        self,
        subject:        str,
        attrs:          dict,
        in_response_to: str,
        session_index:  str = None,
    ) -> BuiltResponse:
        response_id  = '_' + uuid.uuid4().hex
        assertion_id = '_' + uuid.uuid4().hex
        now = datetime.now(timezone.utc)
        now_str    = now.strftime('%Y-%m-%dT%H:%M:%SZ')
        expiry_str = (now + timedelta(seconds=self.config.session_ttl_seconds)).strftime('%Y-%m-%dT%H:%M:%SZ')
        session_idx = session_index or '_' + uuid.uuid4().hex[:16]

        # Build Response
        response = ET.Element(_SAP + 'Response')
        response.set('ID',           response_id)
        response.set('Version',      '2.0')
        response.set('IssueInstant', now_str)
        response.set('Destination',  self.config.acs_url)
        response.set('InResponseTo', in_response_to)

        issuer_el = ET.SubElement(response, _SA + 'Issuer')
        issuer_el.text = self.config.idp_entity_id

        status = ET.SubElement(response, _SAP + 'Status')
        status_code = ET.SubElement(status, _SAP + 'StatusCode')
        status_code.set('Value', STATUS_SUCCESS)

        # Build and sign Assertion
        assertion = self._build_assertion(
            assertion_id, subject, attrs, in_response_to,
            now_str, expiry_str, session_idx
        )
        sign_element(assertion, self.private_key, self.certificate, assertion_id)
        response.append(assertion)

        post_value = base64.b64encode(
            ET.tostring(response, encoding='unicode').encode('utf-8')
        ).decode('ascii')

        return BuiltResponse(
            element=response,
            response_id=response_id,
            assertion_id=assertion_id,
            post_value=post_value,
        )

    def _build_assertion(
        self,
        assertion_id:  str,
        subject:       str,
        attrs:         dict,
        in_response_to: str,
        now_str:       str,
        expiry_str:    str,
        session_index: str,
    ) -> ET.Element:
        assertion = ET.Element(_SA + 'Assertion')
        assertion.set('ID',          assertion_id)
        assertion.set('Version',     '2.0')
        assertion.set('IssueInstant', now_str)

        issuer = ET.SubElement(assertion, _SA + 'Issuer')
        issuer.text = self.config.idp_entity_id

        # Subject
        subject_el = ET.SubElement(assertion, _SA + 'Subject')
        nameid = ET.SubElement(subject_el, _SA + 'NameID')
        nameid.set('Format', TRANSIENT_FMT)
        nameid.text = subject
        subj_confirm = ET.SubElement(subject_el, _SA + 'SubjectConfirmation')
        subj_confirm.set('Method', BEARER_METHOD)
        subj_confirm_data = ET.SubElement(subj_confirm, _SA + 'SubjectConfirmationData')
        subj_confirm_data.set('InResponseTo', in_response_to)
        subj_confirm_data.set('NotOnOrAfter', expiry_str)
        subj_confirm_data.set('Recipient',    self.config.acs_url)

        # Conditions
        conditions = ET.SubElement(assertion, _SA + 'Conditions')
        conditions.set('NotBefore',    now_str)
        conditions.set('NotOnOrAfter', expiry_str)
        audience_restriction = ET.SubElement(conditions, _SA + 'AudienceRestriction')
        audience = ET.SubElement(audience_restriction, _SA + 'Audience')
        audience.text = self.config.sp_entity_id

        # AuthnStatement
        authn_stmt = ET.SubElement(assertion, _SA + 'AuthnStatement')
        authn_stmt.set('AuthnInstant', now_str)
        authn_stmt.set('SessionIndex', session_index)
        authn_context = ET.SubElement(authn_stmt, _SA + 'AuthnContext')
        authn_class_ref = ET.SubElement(authn_context, _SA + 'AuthnContextClassRef')
        authn_class_ref.text = AUTHN_PASSWORD

        # AttributeStatement
        if attrs:
            attr_stmt = ET.SubElement(assertion, _SA + 'AttributeStatement')
            for attr_name, values in attrs.items():
                attr_el = ET.SubElement(attr_stmt, _SA + 'Attribute')
                attr_el.set('Name', attr_name)
                attr_el.set('NameFormat', 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic')
                for val in values:
                    val_el = ET.SubElement(attr_el, _SA + 'AttributeValue')
                    val_el.set('{http://www.w3.org/2001/XMLSchema-instance}type', 'xs:string')
                    val_el.text = val

        return assertion
