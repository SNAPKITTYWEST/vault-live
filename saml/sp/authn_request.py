"""
saml/sp/authn_request.py
SAML AuthnRequest builder: XML construction, C14N, RSA-SHA256 signing,
Base64 + deflate encoding for HTTP-Redirect binding.
"""

import base64
import uuid
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

from crypto.xml_dsig import sign_element, exclusive_c14n

SAML_NS  = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
_SA  = "{%s}" % SAML_NS
_SAP = "{%s}" % SAMLP_NS

REDIRECT_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
POST_BINDING     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"


@dataclass
class AuthnRequestConfig:
    sp_entity_id:    str
    idp_sso_url:     str
    acs_url:         str
    private_key:     object   # RSAPrivateKey
    certificate:     object   # x509.Certificate


@dataclass
class SignedRequest:
    xml_element:  ET.Element
    redirect_url: str
    request_id:   str
    post_value:   str


class AuthnRequestBuilder:
    def __init__(self, config: AuthnRequestConfig):
        self.config = config

    def build(self) -> ET.Element:
        request_id = '_' + uuid.uuid4().hex
        now        = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

        root = ET.Element(_SAP + 'AuthnRequest')
        root.set('ID',                         request_id)
        root.set('Version',                    '2.0')
        root.set('IssueInstant',               now)
        root.set('Destination',                self.config.idp_sso_url)
        root.set('ProtocolBinding',            POST_BINDING)
        root.set('AssertionConsumerServiceURL', self.config.acs_url)

        issuer = ET.SubElement(root, _SA + 'Issuer')
        issuer.text = self.config.sp_entity_id

        nameid_policy = ET.SubElement(root, _SAP + 'NameIDPolicy')
        nameid_policy.set('AllowCreate', 'true')
        nameid_policy.set('Format', 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient')

        return root

    def sign(self, element: ET.Element) -> ET.Element:
        request_id = element.get('ID', '_unknown')
        sign_element(element, self.config.private_key, self.config.certificate, request_id)
        return element

    def encode_redirect(self, element: ET.Element) -> str:
        """Deflate + Base64 + URL-encode for HTTP-Redirect binding SAMLRequest param."""
        xml_bytes = ET.tostring(element, encoding='unicode').encode('utf-8')
        compressed = zlib.compress(xml_bytes)[2:-4]  # raw deflate (strip zlib header/trailer)
        b64 = base64.b64encode(compressed).decode('ascii')
        from urllib.parse import quote
        return quote(b64)

    def encode_post(self, element: ET.Element) -> str:
        """Base64-encode for HTTP-POST binding SAMLRequest field."""
        xml_bytes = ET.tostring(element, encoding='unicode').encode('utf-8')
        return base64.b64encode(xml_bytes).decode('ascii')

    def build_and_sign(self) -> SignedRequest:
        element    = self.build()
        request_id = element.get('ID', '_unknown')
        self.sign(element)
        redirect_encoded = self.encode_redirect(element)
        post_encoded     = self.encode_post(element)
        redirect_url = (
            f"{self.config.idp_sso_url}"
            f"?SAMLRequest={redirect_encoded}"
        )
        return SignedRequest(
            xml_element=element,
            redirect_url=redirect_url,
            request_id=request_id,
            post_value=post_encoded,
        )
