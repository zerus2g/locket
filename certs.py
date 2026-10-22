"""
certs.py - Certificate generation & management for Locket Gold Unlocker
Generates Root CA and wildcard/SAN Server Certificate for HTTPS MITM.
"""

import os
import base64
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

CERT_DIR = os.path.join(os.path.dirname(__file__), "certs")
CA_KEY_PATH = os.path.join(CERT_DIR, "ca.key")
CA_CRT_PATH = os.path.join(CERT_DIR, "ca.crt")
SERVER_KEY_PATH = os.path.join(CERT_DIR, "server.key")
SERVER_CRT_PATH = os.path.join(CERT_DIR, "server.crt")


def ensure_cert_dir():
    if not os.path.exists(CERT_DIR):
        os.makedirs(CERT_DIR, exist_ok=True)


def generate_ca():
    """Generates Root CA key and certificate valid for 10 years."""
    ensure_cert_dir()
    if os.path.exists(CA_KEY_PATH) and os.path.exists(CA_CRT_PATH):
        print("[*] Root CA already exists.")
        return load_ca()

    print("[+] Generating new Root CA...")
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Locket Gold Unlocker"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Locket Gold Root CA"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    with open(CA_KEY_PATH, "wb") as f:
        f.write(
            ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(CA_CRT_PATH, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] Root CA saved to: {CA_CRT_PATH}")
    return ca_key, ca_cert


def load_ca():
    with open(CA_KEY_PATH, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(CA_CRT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_key, ca_cert


def generate_server_cert(extra_ips=None, extra_domains=None):
    """Generates server certificate signed by CA covering RevenueCat & Firebase domains."""
    ensure_cert_dir()
    ca_key, ca_cert = generate_ca()

    print("[+] Generating Server TLS Certificate...")
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Locket Gold Server"),
        x509.NameAttribute(NameOID.COMMON_NAME, "api.revenuecat.com"),
    ])

    import ipaddress
    san_list = [
        x509.DNSName("api.revenuecat.com"),
        x509.DNSName("firebaseremoteconfig.googleapis.com"),
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ]

    if extra_ips:
        for ip_str in extra_ips:
            try:
                san_list.append(x509.IPAddress(ipaddress.IPv4Address(ip_str)))
            except Exception:
                pass

    if extra_domains:
        for d in extra_domains:
            san_list.append(x509.DNSName(d))

    now = datetime.datetime.now(datetime.timezone.utc)
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    with open(SERVER_KEY_PATH, "wb") as f:
        f.write(
            server_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(SERVER_CRT_PATH, "wb") as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] Server Certificate saved to: {SERVER_CRT_PATH}")
    return server_key, server_cert


def get_ca_der_base64():
    """Returns base64 DER string of current CA certificate for mobileconfig."""
    _, ca_cert = generate_ca()
    der = ca_cert.public_bytes(serialization.Encoding.DER)
    return base64.b64encode(der).decode("ascii")


if __name__ == "__main__":
    generate_ca()
    generate_server_cert(extra_ips=["192.168.137.155"])
    print("\n[+] Base64 DER Root CA:")
    print(get_ca_der_base64())
