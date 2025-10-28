"""
"""
from __future__ import annotations
import json
from typing import Dict
from .mac import _cargar_o_crear_clave_mac, calcular_hmac_sha256, verificar_hmac_sha256

# Nombre del fichero con la clave MAC (misma convención usada en el proyecto)
MAC_KEY_FILE = "clave_mac_usuarios.bin"


def _contenido_para_mac(registro: Dict) -> str:
    """Construye la representación JSON determinista usada para el cálculo de la MAC.

    Sólo incluye los campos relevantes y asegura orden y separadores constantes.
    """
    contenido = {
        "email": registro.get("email", ""),
        "password": registro.get("password", ""),
        "fecha_registro": registro.get("fecha_registro", ""),
    }
    return json.dumps(contenido, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def generar_mac_usuario(registro: Dict) -> str:
    """Genera y devuelve la MAC (base64) para un registro de usuario.

    Ejemplo de uso:
        mac = generar_mac_usuario(user_record)
    """
    clave = _cargar_o_crear_clave_mac(MAC_KEY_FILE)
    contenido = _contenido_para_mac(registro)
    return calcular_hmac_sha256(clave, contenido)


def verificar_mac_usuario(registro: Dict) -> bool:
    """Verifica la MAC presente en el registro. Devuelve True si es válida.

    Si el registro no contiene campo 'mac' devuelve False.
    """
    mac_esperada = registro.get("mac")
    if not mac_esperada:
        return False
    clave = _cargar_o_crear_clave_mac(MAC_KEY_FILE)
    contenido = _contenido_para_mac(registro)
    return verificar_hmac_sha256(clave, contenido, mac_esperada)
