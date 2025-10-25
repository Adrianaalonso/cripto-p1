"""Compat layer: reexporta las funciones del paquete `crypto`.

Este archivo mantiene la compatibilidad con el resto del proyecto que
importa `funciones_cripto`. No deberías necesitar cambiar los imports
en otros módulos.
"""

from crypto.hash_contraseña import pbkdf2_hash as _pbkdf2_hash, verificar_password as _verificar_password, generar_clave_aes
from crypto.cifrado_simétrico import (
    cifrar_mensaje,
    descifrar_mensaje,
    _cargar_o_crear_clave_maestra,
    cifrar_para_log,
    descifrar_de_log,
)
from crypto.mac import (
    generar_clave_mac,
    calcular_hmac_sha256,
    verificar_hmac_sha256,
    calcular_hmac_sha512,
    verificar_hmac_sha512,
    _cargar_o_crear_clave_mac,
)
from crypto.cifrado_hibrido import (
    generar_par_claves_rsa,
    cargar_clave_publica_rsa,
    cargar_clave_privada_rsa,
    cifrado_hibrido_voto,
    descifrado_hibrido_voto,
    crear_claves_administrador,
)

__all__ = [
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
