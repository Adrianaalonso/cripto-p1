"""Mensajes comunes"""
LINEA_MENU = "=" * 50
TITULO_MENU = "      *SISTEMA DE VOTACIÓN INTELIGENTE*"
OP_INICIAR = "1. Iniciar Sesión"
OP_REGISTRARSE = "2. Registrarse"
OP_SALIR = "3. Salir"
LINEA_VOTACION = "=" * 40
BIENVENIDA_FMT = "   BIENVENIDO/A: {user}"
TITULO_VOTACION = "   SISTEMA DE VOTACIÓN"
OP_VOTAR = "1. Votar"
OP_VER_RESULTADOS = "2. Ver resultados"
OP_CERRAR_SESION = "3. Cerrar sesión"
INICIANDO = "Iniciando Sistema de Votación..."
GRACIAS = "¡Gracias por usar el Sistema de Votación!"
OPCION_INVALIDA = "Opción no válida. Intente nuevamente."
HASTA_LUEGO = "¡Hasta luego!"
HASTA_LUEGO_FMT = " Hasta luego, {user}!"
YA_VOTASTE = "Ya has votado anteriormente. No puedes votar nuevamente."
OPCIONES_VOTACION = "--- OPCIONES DE VOTACIÓN ---"
VOTO_CANCELAR = "0. Cancelar"
VOTO_GUARDADO_FMT = "Voto anónimo cifrado híbrido + HMAC guardado en: {path}"
VOTO_REGISTRADO_FMT = "Voto registrado para: {opcion}"
PROMPT_SELECCIONAR = "\nSeleccione una opción: "
PROMPT_SELECCION_VOTO = "\nSeleccione su opción (1 o 2): "
PROMPT_USUARIO = "Ingrese nombre de usuario: "
PROMPT_CORREO = "Ingrese su email: "
PROMPT_CODIGO = "Ingresa el código de 6 dígitos: "
PROMPT_USUARIO_ADMIN = " Usuario admin: "
PROMPT_CLAVE_ADMIN = "Ingrese clave de administrador: "
PROMPT_LOGIN_USERNAME = "Nombre de usuario: "
ACCESO_ADMIN = "\n--- ACCESO ADMINISTRATIVO ---"
ACCESO_AUTORIZADO = "\n--- ACCESO ADMINISTRATIVO AUTORIZADO ---"
CLAVE_ADMIN_INCORRECTA = "Clave de administrador incorrecta."
SIN_LOG_EXPORTAR = "No hay log cifrado que exportar."
PROCESANDO_LOG = "Acceso autorizado. Procesando log..."
ADMIN_PANEL_TITLE = "   PANEL DE ADMINISTRADOR"
ADMIN_MENU_LINE = "=" * 40
ADMIN_OP_DESCIFRAR = "1. Descifrar votos híbridos con HMAC"
ADMIN_OP_CERRAR = "2. Cerrar sesión"
NO_VOTES_CIPHERED = " No hay votos cifrados para descifrar."
NO_PRIVATE_KEY = " No se encuentra la clave privada del administrador."

# Mensajes cifrado híbrido
PREFIJO_HIBRIDO = "[LOG HÍBRIDO]"
CIFRADO_HIBRIDO_FMT = "[LOG HÍBRIDO] Cifrando voto: {seleccion}"
CIFRADO_OK = "[LOG HÍBRIDO] Voto cifrado con AES-GCM-256 + RSA-2048"
HMAC_OK = "[LOG HÍBRIDO] HMAC-SHA256 generado"
GUARDADO_HIBRIDO_FMT = "[LOG HÍBRIDO] Guardado en: {archivo}"
# Plantillas de procesamiento / errores
PROCESANDO_ENTRADA_FMT = "Procesando entrada {n}..."
ERROR_ENTRADA_FMT = "Error procesando línea {n}: {e}"
LOG_EXPORTADO_FMT = " Log descifrado exportado en: {salida}"
ENTRADAS_CON_HMAC_FMT = " {count} entradas incluyen información HMAC"
ERROR_ESCRIBIR_ARCHIVO_FMT = " Error escribiendo archivo: {e}"


def bienvenida(user: str) -> str:
    return BIENVENIDA_FMT.format(user=user)


def despedida(user: str | None = None) -> str:
    return HASTA_LUEGO_FMT.format(user=user) if user else HASTA_LUEGO


def procesando_entrada(n: int) -> str:
    return PROCESANDO_ENTRADA_FMT.format(n=n)


def error_entrada(n: int, e: Exception) -> str:
    return ERROR_ENTRADA_FMT.format(n=n, e=e)
