"""
crypto/xml_encrypt.py
XML Encryption for SAML assertions: AES-256-GCM payload, RSA-OAEP key wrap.
Pure stdlib + cryptography library.
"""

import base64
import os
from xml.etree import ElementTree as ET

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509 import Certificate

XENC_NS = "http://www.w3.org/2001/04/xmlenc#"
DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"
_XE = "{%s}" % XENC_NS
_DS = "{%s}" % DSIG_NS

AES256_GCM_ALG = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
RSA_OAEP_ALG   = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"


class DecryptionError(Exception):
    pass


def encrypt_assertion(assertion: ET.Element, sp_cert: Certificate) -> ET.Element:
    """
    Wrap a saml:Assertion in an xenc:EncryptedAssertion.
    Uses AES-256-GCM for the assertion, RSA-OAEP for the symmetric key.
    """
    from crypto.xml_dsig import exclusive_c14n
    plaintext = exclusive_c14n(assertion)

    # Generate AES-256-GCM key + nonce
    aes_key = os.urandom(32)
    nonce   = os.urandom(12)
    aesgcm  = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # ciphertext includes 16-byte GCM tag

    # RSA-OAEP encrypt the AES key
    encrypted_key = sp_cert.public_key().encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    # Build xenc:EncryptedAssertion tree
    enc_assertion = ET.Element('{urn:oasis:names:tc:SAML:2.0:assertion}EncryptedAssertion')

    enc_data = ET.SubElement(enc_assertion, _XE + 'EncryptedData')
    enc_data.set('Type', 'http://www.w3.org/2001/04/xmlenc#Element')

    enc_method = ET.SubElement(enc_data, _XE + 'EncryptionMethod')
    enc_method.set('Algorithm', AES256_GCM_ALG)

    key_info = ET.SubElement(enc_data, _DS + 'KeyInfo')
    enc_key_el = ET.SubElement(key_info, _XE + 'EncryptedKey')
    key_enc_method = ET.SubElement(enc_key_el, _XE + 'EncryptionMethod')
    key_enc_method.set('Algorithm', RSA_OAEP_ALG)
    key_cipher = ET.SubElement(enc_key_el, _XE + 'CipherData')
    key_cipher_val = ET.SubElement(key_cipher, _XE + 'CipherValue')
    key_cipher_val.text = base64.b64encode(encrypted_key).decode('ascii')

    cipher_data = ET.SubElement(enc_data, _XE + 'CipherData')
    cipher_value = ET.SubElement(cipher_data, _XE + 'CipherValue')
    # Store nonce prepended to ciphertext
    cipher_value.text = base64.b64encode(nonce + ciphertext).decode('ascii')

    return enc_assertion


def decrypt_assertion(encrypted_assertion: ET.Element, sp_private_key) -> ET.Element:
    """
    Decrypt an xenc:EncryptedAssertion back to saml:Assertion.
    """
    enc_data = encrypted_assertion.find(_XE + 'EncryptedData')
    if enc_data is None:
        raise DecryptionError("No xenc:EncryptedData found")

    # Extract encrypted AES key
    key_cipher_val = encrypted_assertion.find(
        f".//{_XE}EncryptedKey/{_XE}CipherData/{_XE}CipherValue"
    )
    if key_cipher_val is None:
        raise DecryptionError("No encrypted key found")
    encrypted_key = base64.b64decode(key_cipher_val.text.strip())

    # Decrypt AES key
    try:
        aes_key = sp_private_key.decrypt(
            encrypted_key,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
    except Exception as e:
        raise DecryptionError(f"Key decryption failed: {e}")

    # Extract ciphertext
    cipher_val_el = enc_data.find(f".//{_XE}CipherData/{_XE}CipherValue")
    if cipher_val_el is None:
        raise DecryptionError("No CipherValue found")
    raw = base64.b64decode(cipher_val_el.text.strip())
    nonce      = raw[:12]
    ciphertext = raw[12:]

    # Decrypt assertion
    aesgcm = AESGCM(aes_key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise DecryptionError(f"AES-GCM decryption failed: {e}")

    return ET.fromstring(plaintext.decode('utf-8'))
