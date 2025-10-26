"""Funciones HMAC y gestión de claves MAC persistentes."""
import os
import base64
import hmac
import hashlib


def generar_clave_mac() -> bytes:
    """Genera una clave aleatoria de 256 bits para HMAC."""
    return os.urandom(32)


def calcular_hmac_sha256(clave_mac: bytes, mensaje: str) -> str:
    mac = hmac.new(clave_mac, mensaje.encode("utf-8"), hashlib.sha256)
    resultado = base64.b64encode(mac.digest()).decode()
    return resultado


def verificar_hmac_sha256(clave_mac: bytes, mensaje: str, mac_esperado: str) -> bool:
    mac_calculado = hmac.new(clave_mac, mensaje.encode("utf-8"), hashlib.sha256)
    mac_esperado_bytes = base64.b64decode(mac_esperado)
    valido = hmac.compare_digest(mac_calculado.digest(), mac_esperado_bytes)
    return valido


def calcular_hmac_sha512(clave_mac: bytes, mensaje: str) -> str:
    mac = hmac.new(clave_mac, mensaje.encode("utf-8"), hashlib.sha512)
    resultado = base64.b64encode(mac.digest()).decode()
    return resultado


def verificar_hmac_sha512(clave_mac: bytes, mensaje: str, mac_esperado: str) -> bool:
    mac_calculado = hmac.new(clave_mac, mensaje.encode("utf-8"), hashlib.sha512)
    mac_esperado_bytes = base64.b64decode(mac_esperado)
    valido = hmac.compare_digest(mac_calculado.digest(), mac_esperado_bytes)
    return valido


def _cargar_o_crear_clave_mac(archivo_clave_mac: str) -> bytes:
    """Carga o crea una clave MAC persistente en disco."""
    if os.path.exists(archivo_clave_mac):
        with open(archivo_clave_mac, "rb") as f:
            key = f.read()
        if len(key) == 32:
            return key
    key = generar_clave_mac()
    with open(archivo_clave_mac, "wb") as f:
        f.write(key)
    try:
        os.chmod(archivo_clave_mac, 0o600)
    except Exception:
        pass
    return key
