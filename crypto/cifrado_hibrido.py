"""Funciones relacionadas con cifrado híbrido RSA + AES-GCM y gestión de claves RSA."""
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def generar_par_claves_rsa():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_pem, public_pem


def cargar_clave_publica_rsa(archivo_clave_pub: str):
    from cryptography.hazmat.primitives import serialization

    if not os.path.exists(archivo_clave_pub):
        raise FileNotFoundError(f"Archivo de clave pública no encontrado: {archivo_clave_pub}")
    with open(archivo_clave_pub, "rb") as f:
        public_pem = f.read()
    public_key = serialization.load_pem_public_key(public_pem, backend=default_backend())
    return public_key


def cargar_clave_privada_rsa(archivo_clave_priv: str):
    from cryptography.hazmat.primitives import serialization

    if not os.path.exists(archivo_clave_priv):
        raise FileNotFoundError(f"Archivo de clave privada no encontrado: {archivo_clave_priv}")
    with open(archivo_clave_priv, "rb") as f:
        private_pem = f.read()
    private_key = serialization.load_pem_private_key(private_pem, password=None, backend=default_backend())
    return private_key


def cifrado_hibrido_voto(voto: str, archivo_clave_pub_admin: str) -> dict:
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes

    ks = os.urandom(32)
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(ks), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    voto_cifrado = encryptor.update(voto.encode("utf-8")) + encryptor.finalize()
    tag = encryptor.tag

    public_key = cargar_clave_publica_rsa(archivo_clave_pub_admin)
    clave_sim_cifrada = public_key.encrypt(
        ks,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    resultado = {
        "voto_cifrado": base64.b64encode(voto_cifrado).decode(),
        "iv": base64.b64encode(iv).decode(),
        "tag": base64.b64encode(tag).decode(),
        "clave_sim_cifrada": base64.b64encode(clave_sim_cifrada).decode(),
        "algoritmo_simetrico": "AES-GCM-256",
        "algoritmo_asimetrico": "RSA-2048-OAEP",
    }
    print("[CIFRADO HÍBRIDO] Voto cifrado con AES-GCM-256")
    return resultado


def descifrado_hibrido_voto(voto_cifrado_hibrido: dict, archivo_clave_priv_admin: str) -> str:
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes

    voto_cifrado = base64.b64decode(voto_cifrado_hibrido["voto_cifrado"])
    iv = base64.b64decode(voto_cifrado_hibrido["iv"])
    tag = base64.b64decode(voto_cifrado_hibrido["tag"])
    clave_sim_cifrada = base64.b64decode(voto_cifrado_hibrido["clave_sim_cifrada"])

    private_key = cargar_clave_privada_rsa(archivo_clave_priv_admin)
    ks = private_key.decrypt(
        clave_sim_cifrada,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    cipher = Cipher(algorithms.AES(ks), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    voto_descifrado = decryptor.update(voto_cifrado) + decryptor.finalize()
    print("[DESCIFRADO HÍBRIDO] Voto descifrado con AES-GCM-256")
    return voto_descifrado.decode("utf-8")


def crear_claves_administrador():
    archivo_priv = "admin_private_key.pem"
    archivo_pub = "admin_public_key.pem"
    if not os.path.exists(archivo_priv) or not os.path.exists(archivo_pub):
        print("Generando par de claves RSA para administrador...")
        private_pem, public_pem = generar_par_claves_rsa()
        with open(archivo_priv, "wb") as f:
            f.write(private_pem)
        with open(archivo_pub, "wb") as f:
            f.write(public_pem)
        try:
            os.chmod(archivo_priv, 0o600)
        except Exception:
            pass
        print("Claves generadas:")
        print(f"   Clave privada: {archivo_priv}")
        print(f"   Clave pública: {archivo_pub}")
    return archivo_priv, archivo_pub
