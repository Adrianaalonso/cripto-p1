import os
import json
import getpass
from datetime import datetime
from crypto import (
    cargar_o_crear_clave_maestra,
    descifrar_de_log,
    cargar_o_crear_clave_mac,
    cifrado_hibrido_voto,
    crear_claves_administrador,
    
)
from crypto.signature_rsa import (
    generar_par_claves_rsa,
    cargar_clave_privada,
    cargar_clave_publica,
    guardar_clave_privada,
    guardar_clave_publica,
    firmar,
)
import hmac
import hashlib
import base64
from data import msj_comunes as msj
import uuid


def exportar_log_descifrado(archivo_log_cifrado, archivo_clave, salida="log_descifrado.jsonl", admin_mode=False):
    # Solicitar clave de administrador solo si no es modo admin
    if not admin_mode:
        print(msj.ACCESO_ADMIN)
        clave_admin = getpass.getpass(msj.PROMPT_CLAVE_ADMIN)

        #verificamos que es el admin
        if clave_admin != "admin123":
            print(msj.CLAVE_ADMIN_INCORRECTA)
            from data import msj_espera
            msj_espera.pause()
            return
    else:
        print(msj.ACCESO_AUTORIZADO)

    if not os.path.exists(archivo_log_cifrado):
        print(msj.SIN_LOG_EXPORTAR)
        from data import msj_espera
        msj_espera.pause()
        return

    print(msj.PROCESANDO_LOG)
    clave = cargar_o_crear_clave_maestra(archivo_clave)
    out = []

    with open(archivo_log_cifrado, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            if not line.strip():
                continue

            try:
                rec = json.loads(line)
                print(msj.procesando_entrada(line_num))

                # Descifrar el mensaje
                try:
                    texto = descifrar_de_log(clave, rec.get("iv_b64"), rec.get("tag_b64"), rec.get("ct_b64"))
                except Exception as e:
                    texto = f"[ERROR DESCIFRADO] {e}"

                # Crear entrada básica
                entrada = {
                    "timestamp": rec.get("timestamp"),
                    "algoritmo": rec.get("algoritmo"),
                    "key_bits": rec.get("key_bits"),
                    "texto": texto,
                }

                # Si tiene información HMAC, agregarla y verificar
                if "mac_algoritmo" in rec:
                    entrada["mac_algoritmo"] = rec.get("mac_algoritmo")
                    entrada["mac_longitud_clave"] = rec.get("mac_longitud_clave")

                    # Verificar HMAC usando el texto descifrado
                    if "mac" in rec:
                        try:
                            # Cargar clave MAC y verificar manualmente (sin import local)
                            clave_mac = cargar_o_crear_clave_mac("json/clave_mac_logs.bin")
                            mac_calculado = hmac.new(clave_mac, texto.encode('utf-8'), hashlib.sha256)
                            mac_esperado = base64.b64decode(rec["mac"])
                            if hmac.compare_digest(mac_calculado.digest(), mac_esperado):
                                entrada["mac_verificacion"] = " VÁLIDO"
                            else:
                                entrada["mac_verificacion"] = " INVÁLIDO"
                        except Exception as e:
                            entrada["mac_verificacion"] = f"Error: {e}"
                    else:
                        entrada["mac_verificacion"] = "Sin MAC"

                out.append(entrada)

            except Exception as e:
                print(msj.error_entrada(line_num, e))
                continue

    # Escribir archivo de salida en jsonl
    try:
        with open(salida, "w", encoding="utf-8") as g:
            for r in out:
                g.write(json.dumps(r, ensure_ascii=False) + "\n")

        print(msj.LOG_EXPORTADO_FMT.format(salida=salida))

        # Contar entradas con HMAC
        con_hmac = sum(1 for r in out if r.get("mac_presente") == "Si")
        if con_hmac > 0:
            print(msj.ENTRADAS_CON_HMAC_FMT.format(count=con_hmac))

    except Exception as e:
        print(msj.ERROR_ESCRIBIR_ARCHIVO_FMT.format(e=e))

    from data import msj_espera
    msj_espera.pause()


# ===== CIFRADO HÍBRIDO + HMAC UNIFICADO =====

def registrar_log_hibrido_hmac(usuario: str, seleccion: str, archivo_log_cifrado):

    #primero creamos claves RSA si no existen
    archivo_priv, archivo_pub = crear_claves_administrador()

    #preparamos el mensaje del voto
    mensaje = f"Voto de {usuario} para {seleccion} @ {datetime.now().isoformat(timespec='seconds')}"

    print(msj.CIFRADO_HIBRIDO_FMT.format(seleccion=seleccion))

    # ciframos el mensaje simetrica y asiméctricamente
    voto_cifrado_hibrido = cifrado_hibrido_voto(mensaje, archivo_pub)

    # HMAC del mensaje original
    clave_mac = cargar_o_crear_clave_mac("json/clave_mac_logs.bin")
    mac = hmac.new(clave_mac, mensaje.encode('utf-8'), hashlib.sha256)
    mac_b64 = base64.b64encode(mac.digest()).decode()

    # ===== Firma digital RSA-PSS (clave del sistema) =====
    # Generar un identificador único para el voto y unificar el timestamp
    vote_id = uuid.uuid4().hex
    timestamp_iso = datetime.now().isoformat(timespec='seconds')

    # canonical content for signature (same fields we HMAC)
    mac_obj = {
        "vote_id": vote_id,
        "voto_cifrado": voto_cifrado_hibrido["voto_cifrado"],
        "iv": voto_cifrado_hibrido["iv"],
        "tag": voto_cifrado_hibrido["tag"],
        "clave_sim_cifrada": voto_cifrado_hibrido["clave_sim_cifrada"],
        "timestamp": timestamp_iso,
    }
    contenido_para_firma = json.dumps(mac_obj, sort_keys=True, separators=(',',':'), ensure_ascii=False).encode('utf-8')

    # Ensure system key pair exists under json/
    sistema_priv = "json/system_private_key.pem"
    sistema_pub = "json/system_public_key.pem"
    if not os.path.exists(sistema_priv) or not os.path.exists(sistema_pub):
        # generar par
        priv_pem, pub_pem = generar_par_claves_rsa(bits=2048)
        # guardar
        os.makedirs("json", exist_ok=True)
        with open(sistema_priv, "wb") as f:
            f.write(priv_pem)
        with open(sistema_pub, "wb") as f:
            f.write(pub_pem)
        print(f"[LOG] Generadas claves de firma del sistema: RSA-2048 -> {sistema_priv}, {sistema_pub}")

    # cargar clave privada (sin passphrase)
    try:
        private_key_obj = cargar_clave_privada(sistema_priv, password=None)
        sig_b64 = firmar(private_key_obj, contenido_para_firma)
    except Exception:
        sig_b64 = None

    #Híbrido + HMAC
    linea_unificada = {
        "vote_id": vote_id,
        "timestamp": timestamp_iso,
        "usuario": usuario,
        "seleccion": seleccion,

        # Datos del cifrado híbrido
        "voto_cifrado": voto_cifrado_hibrido["voto_cifrado"],
        "iv": voto_cifrado_hibrido["iv"],
    "tag": voto_cifrado_hibrido["tag"],
        "clave_sim_cifrada": voto_cifrado_hibrido["clave_sim_cifrada"],

        # Algoritmos utilizados
        "algoritmo_simetrico": voto_cifrado_hibrido["algoritmo_simetrico"],
        "algoritmo_asimetrico": voto_cifrado_hibrido["algoritmo_asimetrico"],

        # Información HMAC
        "mac_algoritmo": "HMAC-SHA256",
        "mac_longitud_clave": 256,
        "mac": mac_b64,
        # Firma digital del sistema (si disponible)
        "sig_alg": "RSA-PSS-SHA256",
        "sig_key_id": "system-rsa-v1",
        "sig": sig_b64,
    }

    # guardamos en un archivo el log unificado
    with open(archivo_log_cifrado, "a", encoding="utf-8") as f:
        f.write(json.dumps(linea_unificada, ensure_ascii=False) + "\n")

    print(msj.CIFRADO_OK)
    print(msj.HMAC_OK)
    print(msj.GUARDADO_HIBRIDO_FMT.format(archivo=archivo_log_cifrado))
