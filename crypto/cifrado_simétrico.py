"""Funciones de cifrado simétrico (AES-GCM) y gestión de claves maestras."""
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def cifrar_mensaje(clave: bytes, mensaje: str) -> str:
    """Cifra un mensaje con AES-GCM y devuelve base64(iv+tag+ciphertext)."""
    iv = os.urandom(12)
    aes = Cipher(algorithms.AES(clave), modes.GCM(iv), backend=default_backend()).encryptor()
    cifrado = aes.update(mensaje.encode("utf-8")) + aes.finalize()
    paquete = iv + aes.tag + cifrado
    resultado = base64.b64encode(paquete).decode()
    print("[LOG] Cifrado realizado con AES-GCM (clave 256 bits)")
    return resultado


def descifrar_mensaje(clave: bytes, cifrado_b64: str) -> str:
    """Descifra el paquete base64(iv+tag+ciphertext) y devuelve el texto."""
    paquete = base64.b64decode(cifrado_b64)
    iv, tag, cifrado = paquete[:12], paquete[12:28], paquete[28:]
    aes = Cipher(algorithms.AES(clave), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    texto = aes.update(cifrado) + aes.finalize()
    print("[LOG] Descifrado realizado con AES-GCM (clave 256 bits)")
    return texto.decode()


def _cargar_o_crear_clave_maestra(archivo_clave: str) -> bytes:
    """Carga una clave AES-256 persistente, o la crea si no existe."""
    if os.path.exists(archivo_clave):
        with open(archivo_clave, "rb") as f:
            key = f.read()
        if len(key) == 32:
            return key
    key = os.urandom(32)
    with open(archivo_clave, "wb") as f:
        f.write(key)
    try:
        os.chmod(archivo_clave, 0o600)
    except Exception:
        pass
    return key


def cifrar_para_log(clave: bytes, mensaje: str) -> dict:
    iv = os.urandom(12)
    aes = Cipher(algorithms.AES(clave), modes.GCM(iv), backend=default_backend()).encryptor()
    ct = aes.update(mensaje.encode("utf-8")) + aes.finalize()
    return {
        "algoritmo": "AES-GCM",
        "key_bits": 256,
        "iv_b64": base64.b64encode(iv).decode(),
        "tag_b64": base64.b64encode(aes.tag).decode(),
        "ct_b64": base64.b64encode(ct).decode(),
    }


def descifrar_de_log(clave: bytes, iv_b64: str, tag_b64: str, ct_b64: str) -> str:
    iv = base64.b64decode(iv_b64)
    tag = base64.b64decode(tag_b64)
    ct = base64.b64decode(ct_b64)
    aes = Cipher(algorithms.AES(clave), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    return (aes.update(ct) + aes.finalize()).decode()
