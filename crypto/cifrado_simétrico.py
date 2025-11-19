"""Funciones de cifrado AES-GCM """
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def cifrar_mensaje(clave: bytes, mensaje: str) -> str:
    """Cifra un mensaje con AES-GCM y devuelve el texto cifrado e iv"""
    iv = os.urandom(12)
    aes = Cipher(algorithms.AES(clave), modes.GCM(iv), backend=default_backend()).encryptor()
    cifrado = aes.update(mensaje.encode("utf-8")) + aes.finalize()
    paquete = iv + aes.tag + cifrado
    resultado = base64.b64encode(paquete).decode()
    return resultado


def descifrar_mensaje(clave: bytes, cifrado_b64: str) -> str:
    """Descifra el mensaje devuelve el texto en claro"""
    paquete = base64.b64decode(cifrado_b64)
    iv, tag, cifrado = paquete[:12], paquete[12:28], paquete[28:]
    aes = Cipher(algorithms.AES(clave), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    texto = aes.update(cifrado) + aes.finalize()
    return texto.decode()


def cargar_o_crear_clave_maestra(archivo_clave: str) -> bytes:
    """Carga una clave AES-256 o la crea si no existe."""
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


def descifrar_de_log(clave: bytes, iv_b64: str, tag_b64: str, ct_b64: str) -> str:
    """Descifra usando componentes base64 (iv, tag, ct) y devuelve el texto claro."""
    if not (iv_b64 and tag_b64 and ct_b64):
        raise ValueError("Componentes de cifrado incompletos")
    iv = base64.b64decode(iv_b64)
    tag = base64.b64decode(tag_b64)
    ct = base64.b64decode(ct_b64)
    aes = Cipher(algorithms.AES(clave), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    texto = aes.update(ct) + aes.finalize()
    return texto.decode()

