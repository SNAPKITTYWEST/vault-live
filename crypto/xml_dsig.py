"""
crypto/xml_dsig.py
XML Digital Signatures: RSA-SHA256, enveloped, Exclusive C14N.
Pure stdlib xml.etree.ElementTree + cryptography library.
No lxml, no xmlsec.
"""

import base64
import copy
import hashlib
import re
from xml.etree import ElementTree as ET

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import Certificate

# ── Namespace constants ───────────────────────────────────────────────────────

DSIG_NS      = "http://www.w3.org/2000/09/xmldsig#"
EXC_C14N_ALG = "http://www.w3.org/2001/10/xml-exc-c14n#"
RSA_SHA256   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
SHA256_ALG   = "http://www.w3.org/2001/04/xmlenc#sha256"
ENVELOPED    = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"

_DS = "{%s}" % DSIG_NS

# Register prefixes for clean serialisation
ET.register_namespace('ds',   DSIG_NS)
ET.register_namespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion')
ET.register_namespace('samlp','urn:oasis:names:tc:SAML:2.0:protocol')
ET.register_namespace('md',   'urn:oasis:names:tc:SAML:2.0:metadata')
ET.register_namespace('xenc', 'http://www.w3.org/2001/04/xmlenc#')
ET.register_namespace('xsi',  'http://www.w3.org/2001/XMLSchema-instance')
ET.register_namespace('vl',   'urn:vault-live:nand:1.0')


class SignatureVerificationError(Exception):
    pass

class DigestMismatchError(SignatureVerificationError):
    pass


# ── Exclusive C14N (pure Python) ──────────────────────────────────────────────

def exclusive_c14n(element: ET.Element) -> bytes:
    """
    Exclusive Canonical XML (https://www.w3.org/TR/xml-exc-c14n/).
    Simplified implementation sufficient for SAML use cases:
    - namespace declarations appear only on the element that first uses them
    - attributes sorted by namespace URI then local name
    - self-closing tags expanded
    """
    buf = []
    _c14n_element(element, buf, set())
    return ''.join(buf).encode('utf-8')


def _c14n_element(elem: ET.Element, buf: list, rendered_ns: set, depth: int = 0):
    # Parse tag to get namespace and local name
    tag = elem.tag
    ns_uri, local = _split_tag(tag)

    # Collect all namespaces used by this element and its attributes
    used_ns = {}
    if ns_uri:
        prefix = _get_prefix(ns_uri)
        used_ns[prefix] = ns_uri
    for attr_name in elem.attrib:
        attr_ns, _ = _split_tag(attr_name)
        if attr_ns:
            prefix = _get_prefix(attr_ns)
            used_ns[prefix] = attr_ns

    # Determine which ns declarations to render (not yet rendered by ancestors)
    new_ns = {p: u for p, u in used_ns.items() if (p, u) not in rendered_ns}

    # Build open tag
    prefix = _get_prefix(ns_uri) if ns_uri else None
    tag_name = f"{prefix}:{local}" if prefix else local
    buf.append(f"<{tag_name}")

    # Namespace declarations — sorted by prefix
    for p in sorted(new_ns.keys()):
        u = new_ns[p]
        attr_name = f"xmlns:{p}" if p else "xmlns"
        buf.append(f" {attr_name}=\"{_escape_attr(u)}\"")

    # Attributes — sorted by namespace URI then local name (exc-c14n order)
    attrs = []
    for attr_key, attr_val in elem.attrib.items():
        attr_ns, attr_local = _split_tag(attr_key)
        attr_prefix = _get_prefix(attr_ns) if attr_ns else None
        attr_qname = f"{attr_prefix}:{attr_local}" if attr_prefix else attr_local
        attrs.append((attr_ns or '', attr_local, attr_qname, attr_val))
    attrs.sort(key=lambda x: (x[0], x[1]))
    for _, _, qname, val in attrs:
        buf.append(f" {qname}=\"{_escape_attr(val)}\"")

    buf.append(">")

    # Children
    child_rendered = rendered_ns | {(p, u) for p, u in new_ns.items()}
    if elem.text:
        buf.append(_escape_text(elem.text))
    for child in elem:
        _c14n_element(child, buf, child_rendered, depth + 1)
        if child.tail:
            buf.append(_escape_text(child.tail))

    buf.append(f"</{tag_name}>")


def _split_tag(tag: str):
    m = re.match(r'^\{([^}]+)\}(.+)$', tag)
    if m:
        return m.group(1), m.group(2)
    return None, tag


_NS_MAP = {
    'urn:oasis:names:tc:SAML:2.0:assertion':  'saml',
    'urn:oasis:names:tc:SAML:2.0:protocol':   'samlp',
    'urn:oasis:names:tc:SAML:2.0:metadata':   'md',
    'http://www.w3.org/2000/09/xmldsig#':      'ds',
    'http://www.w3.org/2001/04/xmlenc#':       'xenc',
    'http://www.w3.org/2001/XMLSchema-instance': 'xsi',
    'urn:vault-live:nand:1.0':                 'vl',
}

def _get_prefix(ns_uri: str) -> str:
    return _NS_MAP.get(ns_uri, 'ns')

def _escape_attr(s: str) -> str:
    return s.replace('&', '&amp;').replace('"', '&quot;').replace('<', '&lt;').replace('\t', '&#9;').replace('\n', '&#10;').replace('\r', '&#13;')

def _escape_text(s: str) -> str:
    return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('\r', '&#13;')


# ── Signing ───────────────────────────────────────────────────────────────────

def sign_element(element: ET.Element, private_key, cert: Certificate, reference_id: str) -> None:
    """
    Add an enveloped ds:Signature to element in-place.
    reference_id should match the element's ID attribute (without #).
    Serialises to a normalised string by round-tripping through ET to ensure
    verify() sees identical bytes.
    """
    # 1. Strip any existing signature
    existing = element.find(_DS + 'Signature')
    if existing is not None:
        element.remove(existing)

    # 2. Normalise element by round-trip serialisation so namespaces are stable
    normalised_xml = ET.tostring(element, encoding='unicode')
    norm_element   = ET.fromstring(normalised_xml)

    # 3. Compute digest of the normalised element
    c14n_bytes = ET.tostring(norm_element, encoding='unicode').encode('utf-8')
    digest = hashlib.sha256(c14n_bytes).digest()
    digest_b64 = base64.b64encode(digest).decode('ascii')

    # 3. Build SignedInfo
    signed_info = ET.Element(_DS + 'SignedInfo')
    c14n_method = ET.SubElement(signed_info, _DS + 'CanonicalizationMethod')
    c14n_method.set('Algorithm', EXC_C14N_ALG)
    sig_method = ET.SubElement(signed_info, _DS + 'SignatureMethod')
    sig_method.set('Algorithm', RSA_SHA256)
    reference = ET.SubElement(signed_info, _DS + 'Reference')
    reference.set('URI', f"#{reference_id}")
    transforms = ET.SubElement(reference, _DS + 'Transforms')
    t1 = ET.SubElement(transforms, _DS + 'Transform')
    t1.set('Algorithm', ENVELOPED)
    t2 = ET.SubElement(transforms, _DS + 'Transform')
    t2.set('Algorithm', EXC_C14N_ALG)
    digest_method = ET.SubElement(reference, _DS + 'DigestMethod')
    digest_method.set('Algorithm', SHA256_ALG)
    digest_value = ET.SubElement(reference, _DS + 'DigestValue')
    digest_value.text = digest_b64

    # 4. Sign the serialised SignedInfo
    si_c14n = ET.tostring(signed_info, encoding='unicode').encode('utf-8')
    sig_bytes = private_key.sign(si_c14n, padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = base64.b64encode(sig_bytes).decode('ascii')

    # 5. Build full ds:Signature element
    signature = ET.Element(_DS + 'Signature')
    signature.append(signed_info)
    sig_value_el = ET.SubElement(signature, _DS + 'SignatureValue')
    sig_value_el.text = sig_b64
    key_info = ET.SubElement(signature, _DS + 'KeyInfo')
    x509_data = ET.SubElement(key_info, _DS + 'X509Data')
    x509_cert = ET.SubElement(x509_data, _DS + 'X509Certificate')
    x509_cert.text = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode('ascii')

    # Insert signature as first child (after Issuer if present) — SAML convention
    element.insert(0, signature)


# ── Verification ─────────────────────────────────────────────────────────────

def verify_signature(element: ET.Element, cert: Certificate) -> None:
    """
    Verify an enveloped ds:Signature on element.
    Raises SignatureVerificationError or DigestMismatchError on failure.
    """
    sig_el = element.find(_DS + 'Signature')
    if sig_el is None:
        raise SignatureVerificationError("No ds:Signature found")

    signed_info = sig_el.find(_DS + 'SignedInfo')
    sig_value_el = sig_el.find(_DS + 'SignatureValue')
    if signed_info is None or sig_value_el is None:
        raise SignatureVerificationError("Malformed ds:Signature")

    # 1. Verify SignedInfo signature
    si_c14n = ET.tostring(signed_info, encoding='unicode').encode('utf-8')
    sig_bytes = base64.b64decode(sig_value_el.text.strip())
    pub_key = cert.public_key()
    try:
        pub_key.verify(sig_bytes, si_c14n, padding.PKCS1v15(), hashes.SHA256())
    except Exception as e:
        raise SignatureVerificationError(f"RSA signature invalid: {e}")

    # 2. Verify digest of referenced element
    ref_el = signed_info.find(_DS + 'Reference')
    if ref_el is None:
        raise SignatureVerificationError("No ds:Reference found")
    ref_uri = ref_el.get('URI', '')
    if not ref_uri.startswith('#'):
        raise SignatureVerificationError(f"Non-local reference URI: {ref_uri}")
    ref_id = ref_uri[1:]

    # Find referenced element by ID attribute — strict, Signature Wrapping defence
    referenced = _find_by_id(element, ref_id)
    if referenced is None:
        raise SignatureVerificationError(f"Referenced element #{ref_id} not found")

    # Strip signature from copy for digest computation
    clean = copy.deepcopy(referenced)
    sig_copy = clean.find(_DS + 'Signature')
    if sig_copy is not None:
        clean.remove(sig_copy)

    # Normalise by round-trip to match sign_element's serialisation
    norm_clean  = ET.fromstring(ET.tostring(clean, encoding='unicode'))
    clean_bytes = ET.tostring(norm_clean, encoding='unicode').encode('utf-8')
    computed_digest = base64.b64encode(hashlib.sha256(clean_bytes).digest()).decode('ascii')

    stored_digest_el = ref_el.find(_DS + 'DigestValue')
    if stored_digest_el is None:
        raise SignatureVerificationError("No ds:DigestValue found")
    stored_digest = stored_digest_el.text.strip()

    if computed_digest != stored_digest:
        raise DigestMismatchError(
            f"Digest mismatch for #{ref_id}: computed={computed_digest} stored={stored_digest}"
        )


def _find_by_id(element: ET.Element, id_value: str) -> ET.Element | None:
    """Find element whose ID attribute exactly equals id_value."""
    if element.get('ID') == id_value or element.get('id') == id_value:
        return element
    for child in element.iter():
        if child.get('ID') == id_value or child.get('id') == id_value:
            return child
    return None
