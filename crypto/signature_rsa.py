"""RSA-PSS signature helpers (RSA key generation, sign, verify).

Uses cryptography. Implements generation of RSA keys, signing with PSS+SHA256
and verification. Exposes simple save/load helpers that write PEM files.
"""
import base64
import os
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


def generar_par_claves_rsa(bits: int = 2048) -> Tuple[bytes, bytes]:
    """Genera un par RSA y devuelve (pem_privado, pem_publico) en bytes."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits, backend=default_backend())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def guardar_clave_privada(ruta: str, private_key_obj, passphrase: bytes | None = None) -> None:
    """Guardar clave privada en `ruta`. Si se proporciona passphrase, se cifra el PEM."""
    if passphrase:
        enc = serialization.BestAvailableEncryption(passphrase)
    else:
        enc = serialization.NoEncryption()
    pem = private_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )
    os.makedirs(os.path.dirname(ruta) or ".", exist_ok=True)
    with open(ruta, "wb") as f:
        f.write(pem)


def guardar_clave_publica(ruta: str, public_pem: bytes) -> None:
    os.makedirs(os.path.dirname(ruta) or ".", exist_ok=True)
    with open(ruta, "wb") as f:
        f.write(public_pem)


def cargar_clave_privada(ruta: str, password: bytes | None = None):
    with open(ruta, "rb") as f:
        data = f.read()
    return serialization.load_pem_private_key(data, password=password, backend=default_backend())


def cargar_clave_publica(ruta: str):
    with open(ruta, "rb") as f:
        data = f.read()
    return serialization.load_pem_public_key(data, backend=default_backend())


def firmar(private_key_obj, mensaje: bytes) -> str:
    """Firma los bytes `mensaje` y devuelve la firma en base64 (RSA-PSS + SHA256)."""
    sig = private_key_obj.sign(
        mensaje,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return base64.b64encode(sig).decode()


def verificar(public_key_obj, mensaje: bytes, firma_b64: str) -> bool:
    """Verifica la firma base64 contra `mensaje`. Devuelve True si OK, False en caso contrario."""
    try:
        sig = base64.b64decode(firma_b64)
        public_key_obj.verify(
            sig,
            mensaje,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False

