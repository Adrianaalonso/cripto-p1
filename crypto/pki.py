"""Módulo PKI (todo en español).

Implementa una CA raíz y una CA subordinada, emisión de certificados X.509
para usuarios, verificación de cadena simple y revocación básica.

Archivos usados:
- json/pki/root_key.pem, root_cert.pem
- json/pki/sub_key.pem, sub_cert.pem
- json/pki/revoked_certs.json
- json/user_certs/<usuario>.pem
- json/keys_log.jsonl (registro de emisiones)
"""
import os
import json
import datetime
from typing import Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs12


PKI_DIR = "json/pki"
CARPETA_CERT_USUARIOS = "json/user_certs"
REGISTRO_CLAVES = "json/keys_log.jsonl"
FICHERO_REVOKED = os.path.join(PKI_DIR, "revoked_certs.json")


def _asegurar_carpetas():
    os.makedirs(PKI_DIR, exist_ok=True)
    os.makedirs(CARPETA_CERT_USUARIOS, exist_ok=True)


def _guardar_pem(ruta: str, datos: bytes) -> None:
    with open(ruta, "wb") as f:
        f.write(datos)


def _leer_pem(ruta: str) -> bytes:
    with open(ruta, "rb") as f:
        return f.read()


def crear_ca_raiz(nombre_comun: str = "AC1 Root", bits: int = 2048, dias: int = 3650) -> Tuple[str, str]:
    """Crea una CA raíz autofirmada y devuelve (ruta_clave_privada, ruta_cert_pem)."""
    _asegurar_carpetas()
    clave = rsa.generate_private_key(public_exponent=65537, key_size=bits, backend=default_backend())
    sujeto = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nombre_comun)])
    ahora = datetime.datetime.now(datetime.timezone.utc)
    certificado = (
        x509.CertificateBuilder()
        .subject_name(sujeto)
        .issuer_name(sujeto)
        .public_key(clave.public_key())
        .serial_number(x509.random_serial_number())
    .not_valid_before(ahora - datetime.timedelta(days=1))
    .not_valid_after(ahora + datetime.timedelta(days=dias))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(x509.KeyUsage(key_cert_sign=True, crl_sign=True, digital_signature=False,
                                      content_commitment=False, key_encipherment=False,
                                      data_encipherment=False, key_agreement=False, encipher_only=False,
                                      decipher_only=False), critical=True)
        .sign(clave, hashes.SHA256(), default_backend())
    )

    ruta_clave = os.path.join(PKI_DIR, "root_key.pem")
    ruta_cert = os.path.join(PKI_DIR, "root_cert.pem")
    _guardar_pem(ruta_clave, clave.private_bytes(encoding=serialization.Encoding.PEM,
                                                format=serialization.PrivateFormat.PKCS8,
                                                encryption_algorithm=serialization.NoEncryption()))
    _guardar_pem(ruta_cert, certificado.public_bytes(serialization.Encoding.PEM))
    return ruta_clave, ruta_cert


def crear_ca_subordinada(ruta_clave_raiz: str, ruta_cert_raiz: str, nombre_comun: str = "AC2 SubCA", bits: int = 2048, dias: int = 1825) -> Tuple[str, str]:
    """Crea una CA subordinada firmada por la CA raíz proporcionada."""
    _asegurar_carpetas()
    clave_raiz = serialization.load_pem_private_key(_leer_pem(ruta_clave_raiz), password=None, backend=default_backend())
    cert_raiz = x509.load_pem_x509_certificate(_leer_pem(ruta_cert_raiz), backend=default_backend())

    clave_sub = rsa.generate_private_key(public_exponent=65537, key_size=bits, backend=default_backend())
    sujeto = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nombre_comun)])
    ahora = datetime.datetime.now(datetime.timezone.utc)
    cert_sub = (
        x509.CertificateBuilder()
        .subject_name(sujeto)
        .issuer_name(cert_raiz.subject)
        .public_key(clave_sub.public_key())
        .serial_number(x509.random_serial_number())
    .not_valid_before(ahora - datetime.timedelta(days=1))
    .not_valid_after(ahora + datetime.timedelta(days=dias))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(key_cert_sign=True, crl_sign=True, digital_signature=False,
                                      content_commitment=False, key_encipherment=False,
                                      data_encipherment=False, key_agreement=False, encipher_only=False,
                                      decipher_only=False), critical=True)
        .sign(clave_raiz, hashes.SHA256(), default_backend())
    )

    ruta_clave_sub = os.path.join(PKI_DIR, "sub_key.pem")
    ruta_cert_sub = os.path.join(PKI_DIR, "sub_cert.pem")
    _guardar_pem(ruta_clave_sub, clave_sub.private_bytes(encoding=serialization.Encoding.PEM,
                                                        format=serialization.PrivateFormat.PKCS8,
                                                        encryption_algorithm=serialization.NoEncryption()))
    _guardar_pem(ruta_cert_sub, cert_sub.public_bytes(serialization.Encoding.PEM))
    return ruta_clave_sub, ruta_cert_sub


def asegurar_pki() -> bool:
    """Asegura que existan la CA raíz y la CA subordinada; las crea si faltan."""
    _asegurar_carpetas()
    ruta_clave_raiz = os.path.join(PKI_DIR, "root_key.pem")
    ruta_cert_raiz = os.path.join(PKI_DIR, "root_cert.pem")
    ruta_clave_sub = os.path.join(PKI_DIR, "sub_key.pem")
    ruta_cert_sub = os.path.join(PKI_DIR, "sub_cert.pem")
    if not os.path.exists(ruta_clave_raiz) or not os.path.exists(ruta_cert_raiz):
        crear_ca_raiz()
    if not os.path.exists(ruta_clave_sub) or not os.path.exists(ruta_cert_sub):
        crear_ca_subordinada(ruta_clave_raiz, ruta_cert_raiz)
    if not os.path.exists(FICHERO_REVOKED):
        with open(FICHERO_REVOKED, "w", encoding="utf-8") as f:
            json.dump([], f)
    return True


def _anotar_emision(metadata: dict) -> None:
    os.makedirs(os.path.dirname(REGISTRO_CLAVES), exist_ok=True)
    with open(REGISTRO_CLAVES, "a", encoding="utf-8") as f:
        f.write(json.dumps(metadata, ensure_ascii=False) + "\n")


def emitir_certificado_usuario(usuario: str, public_key_pem: bytes, dias: int = 730, ruta_clave_emisor: str = None, ruta_cert_emisor: str = None) -> Tuple[str, int]:
    """Emite un certificado X.509 para la clave pública del usuario y devuelve (ruta_cert, serial)."""
    asegurar_pki()
    if ruta_clave_emisor is None:
        ruta_clave_emisor = os.path.join(PKI_DIR, "sub_key.pem")
    if ruta_cert_emisor is None:
        ruta_cert_emisor = os.path.join(PKI_DIR, "sub_cert.pem")

    clave_emisor = serialization.load_pem_private_key(_leer_pem(ruta_clave_emisor), password=None, backend=default_backend())
    cert_emisor = x509.load_pem_x509_certificate(_leer_pem(ruta_cert_emisor), backend=default_backend())

    clave_publica = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
    sujeto = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, usuario)])
    ahora = datetime.datetime.now(datetime.timezone.utc)
    serial = x509.random_serial_number()
    certificado = (
        x509.CertificateBuilder()
        .subject_name(sujeto)
        .issuer_name(cert_emisor.subject)
        .public_key(clave_publica)
        .serial_number(serial)
        .not_valid_before(ahora - datetime.timedelta(days=1))
        .not_valid_after(ahora + datetime.timedelta(days=dias))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True, content_commitment=False,
                                      data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                      crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.EMAIL_PROTECTION]), critical=False)
        .sign(clave_emisor, hashes.SHA256(), default_backend())
    )

    certificado_pem = certificado.public_bytes(serialization.Encoding.PEM)
    ruta_cert_usuario = os.path.join(CARPETA_CERT_USUARIOS, f"{usuario}.pem")
    _guardar_pem(ruta_cert_usuario, certificado_pem)

    # Registrar metadatos
    metadata = {
        "when": ahora.isoformat(),
        "user": usuario,
        "serial": str(serial),
        "issuer": cert_emisor.subject.rfc4514_string(),
        "subject": sujeto.rfc4514_string(),
        "algoritmo": "RSA",
        "longitud_clave": getattr(clave_publica, 'key_size', None),
    }
    _anotar_emision(metadata)
    return ruta_cert_usuario, serial


def _esta_revocado(serial) -> bool:
    if not os.path.exists(FICHERO_REVOKED):
        return False
    try:
        with open(FICHERO_REVOKED, "r", encoding="utf-8") as f:
            lista = json.load(f)
        return str(serial) in [str(x) for x in lista]
    except Exception:
        return False


def revocar_certificado(serial) -> bool:
    _asegurar_carpetas()
    if not os.path.exists(FICHERO_REVOKED):
        with open(FICHERO_REVOKED, "w", encoding="utf-8") as f:
            json.dump([], f)
    try:
        with open(FICHERO_REVOKED, "r", encoding="utf-8") as f:
            lista = json.load(f)
    except Exception:
        lista = []
    if str(serial) in [str(x) for x in lista]:
        return False
    lista.append(str(serial))
    with open(FICHERO_REVOKED, "w", encoding="utf-8") as f:
        json.dump(lista, f)
    return True


def verificar_cadena_certificado(cert_pem: bytes) -> Tuple[bool, str]:
    """Verifica la cadena usuario->subCA->root, validez temporal y revocación.
    Devuelve (True, '') o (False, motivo).
    """
    asegurar_pki()
    try:
        cert_usuario = x509.load_pem_x509_certificate(cert_pem, backend=default_backend())
        cert_sub = x509.load_pem_x509_certificate(_leer_pem(os.path.join(PKI_DIR, "sub_cert.pem")), backend=default_backend())
        cert_root = x509.load_pem_x509_certificate(_leer_pem(os.path.join(PKI_DIR, "root_cert.pem")), backend=default_backend())

        ahora = datetime.datetime.now(datetime.timezone.utc)
        # use UTC-aware properties to avoid CryptographyDeprecationWarning
        not_before = getattr(cert_usuario, 'not_valid_before_utc', None)
        not_after = getattr(cert_usuario, 'not_valid_after_utc', None)
        if not_before is None or not_after is None:
            # fallback to older properties (should be rare); make them timezone-aware
            not_before = cert_usuario.not_valid_before.replace(tzinfo=datetime.timezone.utc)
            not_after = cert_usuario.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        if not_before > ahora or not_after < ahora:
            return False, "Certificado de usuario fuera de validez"

        if _esta_revocado(cert_usuario.serial_number):
            return False, "Certificado revocado"

        try:
            pub_sub = cert_sub.public_key()
            pub_sub.verify(
                cert_usuario.signature,
                cert_usuario.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert_usuario.signature_hash_algorithm,
            )
        except Exception as e:
            return False, f"Firma del certificado de usuario no verificada: {e}"

        try:
            pub_root = cert_root.public_key()
            pub_root.verify(
                cert_sub.signature,
                cert_sub.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert_sub.signature_hash_algorithm,
            )
        except Exception as e:
            return False, f"Firma de la CA subordinada no verificada: {e}"

        return True, "Cadena válida"
    except Exception as e:
        return False, f"Error verificando cadena: {e}"


def exportar_usuario_a_pfx(usuario: str, private_key_obj, ruta_cert_usuario: str, passphrase: str, destino: str = None) -> str:
    """Exporta la clave privada y el certificado del usuario a un archivo PKCS#12 (.pfx) protegido por passphrase.
    Devuelve la ruta del PFX creado.
    """
    _asegurar_carpetas()
    os.makedirs(os.path.join('json', 'user_keys'), exist_ok=True)
    if destino is None:
        destino = os.path.join('json', 'user_keys', f"{usuario}.pfx")

    # Cargar certificado de usuario
    cert_bytes = _leer_pem(ruta_cert_usuario)
    cert_obj = x509.load_pem_x509_certificate(cert_bytes, backend=default_backend())

    # Intentar cargar certificados adicionales (sub + root) para incluir en el PFX
    additional = []
    try:
        sub_p = _leer_pem(os.path.join(PKI_DIR, 'sub_cert.pem'))
        additional.append(x509.load_pem_x509_certificate(sub_p, backend=default_backend()))
    except Exception:
        pass
    try:
        root_p = _leer_pem(os.path.join(PKI_DIR, 'root_cert.pem'))
        additional.append(x509.load_pem_x509_certificate(root_p, backend=default_backend()))
    except Exception:
        pass

    if passphrase is None:
        passphrase_bytes = None
    else:
        passphrase_bytes = passphrase.encode('utf-8')

    pfx_bytes = pkcs12.serialize_key_and_certificates(
        name=usuario.encode('utf-8'),
        key=private_key_obj,
        cert=cert_obj,
        cas=additional if additional else None,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase_bytes) if passphrase_bytes else serialization.NoEncryption(),
    )

    with open(destino, 'wb') as pf:
        pf.write(pfx_bytes)

    return destino


def cargar_clave_desde_pfx(ruta_pfx: str, passphrase: str):
    """Carga la clave privada desde un archivo PKCS#12 (.pfx) y devuelve el objeto private_key.
    Si la passphrase es incorrecta lanzará excepción.
    """
    with open(ruta_pfx, 'rb') as f:
        data = f.read()
    pass_bytes = passphrase.encode('utf-8') if passphrase is not None else None
    private_key, cert, additional = pkcs12.load_key_and_certificates(data, pass_bytes, backend=default_backend())
    return private_key
