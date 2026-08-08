"""
crypto/keys.py
RSA key lifecycle: generate, self-sign X.509, serialise/load PEM.
Pure stdlib + cryptography library. No lxml, no xmlsec.
"""

import datetime
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


@dataclass
class KeyPair:
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey
    certificate: x509.Certificate
    entity_id: str


def generate_key_pair(entity_id: str, key_size: int = 2048) -> KeyPair:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, entity_id),
    ])

    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    return KeyPair(
        private_key=private_key,
        public_key=public_key,
        certificate=cert,
        entity_id=entity_id,
    )


def save_pem(key_pair: KeyPair, private_path: str, cert_path: str) -> None:
    with open(private_path, 'wb') as f:
        f.write(key_pair.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(cert_path, 'wb') as f:
        f.write(key_pair.certificate.public_bytes(serialization.Encoding.PEM))


def load_private_key(path: str) -> rsa.RSAPrivateKey:
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_certificate(path: str) -> x509.Certificate:
    with open(path, 'rb') as f:
        return x509.load_pem_x509_certificate(f.read())


def cert_to_b64(cert: x509.Certificate) -> str:
    import base64
    der = cert.public_bytes(serialization.Encoding.DER)
    return base64.b64encode(der).decode('ascii')
