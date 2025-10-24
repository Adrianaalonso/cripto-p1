# Funciones criptográficas exactas del sistema_votacion.py original
import os
import base64
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from configuracion import PBKDF2_ITERS

def _pbkdf2_hash(password: str, salt: bytes=None, iters = PBKDF2_ITERS):
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iters)
    return f"pbkdf2$sha256${iters}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"

def _verificar_password(password: str, stored: str) -> bool:
    try:
        scheme, algo, iters, salt_b64, dk_b64 = stored.split('$', 4)
        assert scheme == 'pbkdf2' and algo == 'sha256'
        salt = base64.b64decode(salt_b64)
        dk_stored = base64.b64decode(dk_b64)
        dk_new = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, int(iters))
        return hmac.compare_digest(dk_new, dk_stored)
    except Exception:
        return False

def generar_clave_aes():
    """Generar clave AES de 256 bits"""
    return os.urandom(32)  # 32 bytes = 256 bits

def cifrar_mensaje(clave, mensaje: str):
    """Cifrar mensaje con AES-GCM"""
    iv = os.urandom(12)  # nonce recomendado para GCM
    aes = Cipher(algorithms.AES(clave), modes.GCM(iv), backend=default_backend()).encryptor()
    cifrado = aes.update(mensaje.encode()) + aes.finalize()
    # empaquetamos IV + tag + texto cifrado
    paquete = iv + aes.tag + cifrado
    resultado = base64.b64encode(paquete).decode()
    print(f"[LOG] Cifrado realizado con AES-GCM (clave 256 bits)")
    print(f"[LOG] Texto original: {mensaje}")
    print(f"[LOG] Texto cifrado (base64): {resultado}\n")
    return resultado

def descifrar_mensaje(clave, cifrado_b64: str):
    """Descifrar mensaje con AES-GCM"""
    paquete = base64.b64decode(cifrado_b64)
    iv, tag, cifrado = paquete[:12], paquete[12:28], paquete[28:]
    aes = Cipher(algorithms.AES(clave), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    texto = aes.update(cifrado) + aes.finalize()
    print(f"[LOG] Descifrado realizado con AES-GCM (clave 256 bits)")
    print(f"[LOG] Texto descifrado: {texto.decode()}\n")
    return texto.decode()

def _cargar_o_crear_clave_maestra(archivo_clave):
    """Clave AES-256 persistente para el log cifrado."""
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

def _cargar_o_crear_clave_mac(archivo_clave_mac):
    """Clave MAC-256 persistente para autenticación."""
    if os.path.exists(archivo_clave_mac):
        with open(archivo_clave_mac, "rb") as f:
            key = f.read()
        if len(key) == 32:
            return key
    key = os.urandom(32)  
    with open(archivo_clave_mac, "wb") as f:
        f.write(key)
    try:
        os.chmod(archivo_clave_mac, 0o600)  
    except Exception:
        pass
    return key

def cifrar_para_log(clave, mensaje: str):
    iv = os.urandom(12)
    aes = Cipher(algorithms.AES(clave), modes.GCM(iv), backend=default_backend()).encryptor()
    ct = aes.update(mensaje.encode()) + aes.finalize()
    return {
        "algoritmo": "AES-GCM",
        "key_bits": 256,
        "iv_b64": base64.b64encode(iv).decode(),
        "tag_b64": base64.b64encode(aes.tag).decode(),
        "ct_b64": base64.b64encode(ct).decode(),
    }

def descifrar_de_log(clave, iv_b64, tag_b64, ct_b64) -> str:
    iv = base64.b64decode(iv_b64)
    tag = base64.b64decode(tag_b64)
    ct  = base64.b64decode(ct_b64)
    aes = Cipher(algorithms.AES(clave), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    return (aes.update(ct) + aes.finalize()).decode()

# ===== FUNCIONES MAC (Códigos de Autenticación de Mensajes) =====

def generar_clave_mac():
    """Generar clave para HMAC de 256 bits"""
    return os.urandom(32)  # 256 bits para HMAC

def calcular_hmac_sha256(clave_mac, mensaje: str):
    """Calcular HMAC-SHA256 para autenticación de mensajes"""
    mac = hmac.new(clave_mac, mensaje.encode('utf-8'), hashlib.sha256)
    resultado = base64.b64encode(mac.digest()).decode()
    print(f"[LOG] HMAC generado con SHA-256 (clave 256 bits)")
    print(f"[LOG] Mensaje original: {mensaje}")
    print(f"[LOG] HMAC-SHA256: {resultado}\n")
    return resultado

def verificar_hmac_sha256(clave_mac, mensaje: str, mac_esperado: str) -> bool:
    """Verificar HMAC-SHA256 para validar integridad"""
    mac_calculado = hmac.new(clave_mac, mensaje.encode('utf-8'), hashlib.sha256)
    mac_esperado_bytes = base64.b64decode(mac_esperado)
    valido = hmac.compare_digest(mac_calculado.digest(), mac_esperado_bytes)
    print(f"[LOG] Verificación HMAC-SHA256: {'✓ VÁLIDO' if valido else '✗ INVÁLIDO'}")
    print(f"[LOG] Mensaje verificado: {mensaje}")
    print(f"[LOG] HMAC esperado: {mac_esperado}")
    print(f"[LOG] Resultado: {'Integridad confirmada' if valido else 'POSIBLE MANIPULACIÓN'}\n")
    return valido

def calcular_hmac_sha512(clave_mac, mensaje: str):
    """Calcular HMAC-SHA512 para logs críticos"""
    mac = hmac.new(clave_mac, mensaje.encode('utf-8'), hashlib.sha512)
    resultado = base64.b64encode(mac.digest()).decode()
    print(f"[LOG] HMAC generado con SHA-512 (clave 256 bits)")
    print(f"[LOG] Mensaje original: {mensaje}")
    print(f"[LOG] HMAC-SHA512: {resultado}\n")
    return resultado

def verificar_hmac_sha512(clave_mac, mensaje: str, mac_esperado: str) -> bool:
    """Verificar HMAC-SHA512 para logs críticos"""
    mac_calculado = hmac.new(clave_mac, mensaje.encode('utf-8'), hashlib.sha512)
    mac_esperado_bytes = base64.b64decode(mac_esperado)
    valido = hmac.compare_digest(mac_calculado.digest(), mac_esperado_bytes)
    print(f"[LOG] Verificación HMAC-SHA512: {'✓ VÁLIDO' if valido else '✗ INVÁLIDO'}")
    print(f"[LOG] Mensaje verificado: {mensaje}")
    print(f"[LOG] HMAC esperado: {mac_esperado}")
    print(f"[LOG] Resultado: {'Integridad confirmada' if valido else 'POSIBLE MANIPULACIÓN'}\n")
    return valido

def _cargar_o_crear_clave_mac(archivo_clave_mac):
    """Cargar o crear clave HMAC persistente"""
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

# ===== CIFRADO HÍBRIDO RSA + AES-GCM =====

def generar_par_claves_rsa():
    """Generar par de claves RSA de 2048 bits"""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    
    # Generar clave privada
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Obtener clave pública
    public_key = private_key.public_key()
    
    # Serializar clave privada
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serializar clave pública
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem

def cargar_clave_publica_rsa(archivo_clave_pub):
    """Cargar clave pública RSA desde archivo"""
    from cryptography.hazmat.primitives import serialization
    
    if not os.path.exists(archivo_clave_pub):
        raise FileNotFoundError(f"Archivo de clave pública no encontrado: {archivo_clave_pub}")
    
    with open(archivo_clave_pub, "rb") as f:
        public_pem = f.read()
    
    public_key = serialization.load_pem_public_key(public_pem, backend=default_backend())
    return public_key

def cargar_clave_privada_rsa(archivo_clave_priv):
    """Cargar clave privada RSA desde archivo"""
    from cryptography.hazmat.primitives import serialization
    
    if not os.path.exists(archivo_clave_priv):
        raise FileNotFoundError(f"Archivo de clave privada no encontrado: {archivo_clave_priv}")
    
    with open(archivo_clave_priv, "rb") as f:
        private_pem = f.read()
    
    private_key = serialization.load_pem_private_key(
        private_pem, 
        password=None, 
        backend=default_backend()
    )
    return private_key

def cifrado_hibrido_voto(voto, archivo_clave_pub_admin):
    """
    Cifrado híbrido: AES-GCM para el voto + RSA para la clave simétrica
    
    Args:
        voto (str): El voto a cifrar
        archivo_clave_pub_admin (str): Archivo con clave pública del administrador
    
    Returns:
        dict: Resultado del cifrado híbrido
    """
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    
    # 1. Generar clave simétrica aleatoria de 256 bits
    ks = os.urandom(32)  # Clave de sesión
    
    # 2. Cifrar el voto con AES-GCM usando Ks
    iv = os.urandom(12)  # IV de 96 bits para GCM
    cipher = Cipher(algorithms.AES(ks), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    voto_cifrado = encryptor.update(voto.encode('utf-8')) + encryptor.finalize()
    tag = encryptor.tag
    
    # 3. Cargar clave pública del administrador
    public_key = cargar_clave_publica_rsa(archivo_clave_pub_admin)
    
    # 4. Cifrar la clave simétrica Ks con RSA
    clave_sim_cifrada = public_key.encrypt(
        ks,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # 5. Preparar resultado
    resultado = {
        "voto_cifrado": base64.b64encode(voto_cifrado).decode(),
        "iv": base64.b64encode(iv).decode(),
        "tag": base64.b64encode(tag).decode(),
        "clave_sim_cifrada": base64.b64encode(clave_sim_cifrada).decode(),
        "algoritmo_simetrico": "AES-GCM-256",
        "algoritmo_asimetrico": "RSA-2048-OAEP"
    }
    
    print(f"[CIFRADO HÍBRIDO] Voto cifrado con AES-GCM-256")
    print(f"[CIFRADO HÍBRIDO] Clave simétrica cifrada con RSA-2048-OAEP")
    print(f"[CIFRADO HÍBRIDO] IV: {resultado['iv']}")
    print(f"[CIFRADO HÍBRIDO] Tag autenticación: {resultado['tag']}")
    
    return resultado

def descifrado_hibrido_voto(voto_cifrado_hibrido, archivo_clave_priv_admin):
    """
    Descifrado híbrido: RSA para obtener clave simétrica + AES-GCM para el voto
    
    Args:
        voto_cifrado_hibrido (dict): Resultado del cifrado híbrido
        archivo_clave_priv_admin (str): Archivo con clave privada del administrador
    
    Returns:
        str: El voto descifrado
    """
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    
    # 1. Extraer datos del cifrado híbrido
    voto_cifrado = base64.b64decode(voto_cifrado_hibrido["voto_cifrado"])
    iv = base64.b64decode(voto_cifrado_hibrido["iv"])
    tag = base64.b64decode(voto_cifrado_hibrido["tag"])
    clave_sim_cifrada = base64.b64decode(voto_cifrado_hibrido["clave_sim_cifrada"])
    
    # 2. Cargar clave privada del administrador
    private_key = cargar_clave_privada_rsa(archivo_clave_priv_admin)
    
    # 3. Descifrar la clave simétrica Ks con RSA
    ks = private_key.decrypt(
        clave_sim_cifrada,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # 4. Descifrar el voto con AES-GCM usando Ks
    cipher = Cipher(algorithms.AES(ks), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    voto_descifrado = decryptor.update(voto_cifrado) + decryptor.finalize()
    
    print(f"[DESCIFRADO HÍBRIDO] Clave simétrica descifrada con RSA-2048-OAEP")
    print(f"[DESCIFRADO HÍBRIDO] Voto descifrado con AES-GCM-256")
    
    return voto_descifrado.decode('utf-8')

def crear_claves_administrador():
    """Crear par de claves RSA para el administrador si no existen"""
    archivo_priv = "admin_private_key.pem"
    archivo_pub = "admin_public_key.pem"
    
    if not os.path.exists(archivo_priv) or not os.path.exists(archivo_pub):
        print("Generando par de claves RSA para administrador...")
        private_pem, public_pem = generar_par_claves_rsa()
        
        # Guardar clave privada
        with open(archivo_priv, "wb") as f:
            f.write(private_pem)
        
        # Guardar clave pública
        with open(archivo_pub, "wb") as f:
            f.write(public_pem)
        
        # Permisos restrictivos para clave privada
        try:
            os.chmod(archivo_priv, 0o600)
        except Exception:
            pass
            
        print("Claves generadas:")
        print(f"   Clave privada: {archivo_priv}")
        print(f"   Clave pública: {archivo_pub}")
    
    return archivo_priv, archivo_pub