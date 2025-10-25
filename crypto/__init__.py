"""Paquete de utilidades criptográficas, dividido en módulos pequeños.

Este paquete reexporta las funciones usadas por el resto del proyecto.
No cambian las firmas públicas, solo se mejora la organización.
"""

from .hash_contraseña import pbkdf2_hash, verificar_password as _verificar_password, generar_clave_aes
from .cifrado_simétrico import (
    cifrar_mensaje,
    descifrar_mensaje,
    _cargar_o_crear_clave_maestra,
    cifrar_para_log,
    descifrar_de_log,
)
from .mac import (
    generar_clave_mac,
    calcular_hmac_sha256,
    verificar_hmac_sha256,
    calcular_hmac_sha512,
    verificar_hmac_sha512,
    _cargar_o_crear_clave_mac,
)
from .cifrado_hibrido import (
    generar_par_claves_rsa,
    cargar_clave_publica_rsa,
    cargar_clave_privada_rsa,
    cifrado_hibrido_voto,
    descifrado_hibrido_voto,
    crear_claves_administrador,
)

__all__ = [
    "pbkdf2_hash",
    "_pbkdf2_hash",
    "_verificar_password",
    "generar_clave_aes",
    "cifrar_mensaje",
    "descifrar_mensaje",
    "_cargar_o_crear_clave_maestra",
    "cifrar_para_log",
    "descifrar_de_log",
    "generar_clave_mac",
    "calcular_hmac_sha256",
    "verificar_hmac_sha256",
    "calcular_hmac_sha512",
    "verificar_hmac_sha512",
    "_cargar_o_crear_clave_mac",
    "generar_par_claves_rsa",
    "cargar_clave_publica_rsa",
    "cargar_clave_privada_rsa",
    "cifrado_hibrido_voto",
    "descifrado_hibrido_voto",
    "crear_claves_administrador",
]

# Backwards-compat aliases (el proyecto original usaba nombres con guion bajo)
_pbkdf2_hash = pbkdf2_hash
