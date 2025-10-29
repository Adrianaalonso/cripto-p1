import json
from .mac import cargar_o_crear_clave_mac, calcular_hmac_sha256, verificar_hmac_sha256

MAC_KEY_FILE = "json/clave_mac_usuarios.bin"

def contenido_para_mac(registro):
    """contenido del JSON para el cálculo de la MAC."""
    contenido = {
        "email": registro.get("email", ""),
        "password": registro.get("password", ""),
        "fecha_registro": registro.get("fecha_registro", ""),
    }
    return json.dumps(contenido, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def generar_mac_usuario(registro):
    """Genera y devuelve la MAC de cada usuario."""
    clave = cargar_o_crear_clave_mac(MAC_KEY_FILE)
    contenido = contenido_para_mac(registro)
    return calcular_hmac_sha256(clave, contenido)

def verificar_mac_usuario(registro):
    """Verifica que la MAC coincida con el registro. Devuelve True si es válida."""
    mac_esperada = registro.get("mac")
    if not mac_esperada:
        return False
    clave = cargar_o_crear_clave_mac(MAC_KEY_FILE)
    contenido = contenido_para_mac(registro)
    return verificar_hmac_sha256(clave, contenido, mac_esperada)
