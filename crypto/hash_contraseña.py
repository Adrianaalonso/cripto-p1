"""Funciones de derivación de clave y utilidades relacionadas con contraseñas."""
import os
import base64
import hashlib
import hmac
from configuracion import PBKDF2_ITERS


def pbkdf2_hash(password: str, salt: bytes = None, iters: int = PBKDF2_ITERS) -> str:
    """Deriva una contraseña con PBKDF2-HMAC-SHA256 y devuelve una cadena serializada.

    Formato: pbkdf2$sha256$<iters>$<salt_b64>$<dk_b64>
    """
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
    return f"pbkdf2$sha256${iters}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verificar_password(password: str, stored: str) -> bool:
    """Verifica una contraseña contra la representación almacenada.

    Devuelve True si coincide, False en caso contrario.
    """
    try:
        scheme, algo, iters, salt_b64, dk_b64 = stored.split("$", 4)
        assert scheme == "pbkdf2" and algo == "sha256"
        salt = base64.b64decode(salt_b64)
        dk_stored = base64.b64decode(dk_b64)
        dk_new = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iters))
        return hmac.compare_digest(dk_new, dk_stored)
    except Exception:
        return False


def generar_clave_aes() -> bytes:
    """Genera y retorna una clave AES-256 (32 bytes)."""
    return os.urandom(32)
