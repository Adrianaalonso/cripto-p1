import os
import json
import getpass
from datetime import datetime
from crypto import (
    _cargar_o_crear_clave_maestra,
    descifrar_de_log,
    _cargar_o_crear_clave_mac,
    cifrado_hibrido_voto,
    crear_claves_administrador,
)
import hmac
import hashlib
import base64
from data import msj_comunes as msj

def exportar_log_descifrado(archivo_log_cifrado, archivo_clave, salida="log_descifrado.jsonl", admin_mode=False):
    # Solicitar clave de administrador solo si no es modo admin
    if not admin_mode:
        print(msj.ACCESO_ADMIN)
        clave_admin = getpass.getpass(msj.PROMPT_CLAVE_ADMIN)

        # Clave de administrador 
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
    clave = _cargar_o_crear_clave_maestra(archivo_clave)
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
                            clave_mac = _cargar_o_crear_clave_mac("clave_mac_logs.bin")
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

    # Escribir archivo de salida
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

    # 1. Crear claves RSA si no existen
    archivo_priv, archivo_pub = crear_claves_administrador()

    # 2. Preparar mensaje del voto
    mensaje = f"Voto de {usuario} para {seleccion} @ {datetime.now().isoformat(timespec='seconds')}"

    print(msj.CIFRADO_HIBRIDO_FMT.format(seleccion=seleccion))
   
    print()

    # 3. Cifrado híbrido del mensaje
    voto_cifrado_hibrido = cifrado_hibrido_voto(mensaje, archivo_pub)

    # 4. Generar HMAC del mensaje original (cálculo local, imports en tope)
    clave_mac = _cargar_o_crear_clave_mac("clave_mac_logs.bin")
    mac = hmac.new(clave_mac, mensaje.encode('utf-8'), hashlib.sha256)
    mac_b64 = base64.b64encode(mac.digest()).decode()

    # 5. Estructura unificada: Híbrido + HMAC
    linea_unificada = {
        "timestamp": datetime.now().isoformat(timespec='seconds'),
        "usuario": usuario,
        "seleccion": seleccion,

        # Datos del cifrado híbrido
        "voto_cifrado": voto_cifrado_hibrido["voto_cifrado"],
        "iv": voto_cifrado_hibrido["iv"],
        "tag_gcm": voto_cifrado_hibrido["tag"],
        "clave_sim_cifrada": voto_cifrado_hibrido["clave_sim_cifrada"],

        # Algoritmos utilizados
        "algoritmo_simetrico": voto_cifrado_hibrido["algoritmo_simetrico"],
        "algoritmo_asimetrico": voto_cifrado_hibrido["algoritmo_asimetrico"],

        # Información HMAC
        "mac_algoritmo": "HMAC-SHA256",
        "mac_longitud_clave": 256,
        "mac": mac_b64,
    }

    # 6. Guardar en archivo log unificado
    with open(archivo_log_cifrado, "a", encoding="utf-8") as f:
        # Escribir en formato legible (indentado) y dejar una línea en blanco
        f.write(json.dumps(linea_unificada, ensure_ascii=False, indent=2) + "\n\n")

    print(msj.CIFRADO_OK)
    print(msj.HMAC_OK)
    print(msj.GUARDADO_HIBRIDO_FMT.format(archivo=archivo_log_cifrado))


def exportar_log_hibrido_descifrado(archivo_log_cifrado, archivo_clave_priv="admin_private_key.pem", salida="out.jsonl", admin_mode=False):
    """
    Exportador compatible con el formato que escribe registrar_log_hibrido_hmac:
    - acepta bloques JSON 'pretty-printed' separados por una línea en blanco
    - descifra usando la clave privada RSA para recuperar la clave simétrica
    - verifica HMAC sobre el texto descifrado
    - escribe JSONL en 'salida' (una entrada por línea)
    """
    # Control de acceso (igual que exportar_log_descifrado)
    if not admin_mode:
        print(msj.ACCESO_ADMIN)
        clave_admin = getpass.getpass(msj.PROMPT_CLAVE_ADMIN)
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

    # importar funciones de descifrado híbrido bajo demanda (puede tener firmas distintas)
    from crypto import descifrado_hibrido_voto, _cargar_o_crear_clave_mac  # descifrado_hibrido_voto puede fallar si no existe

    out = []

    # Leer todo y separar por bloques (cada bloque es un JSON 'pretty' seguido de línea en blanco)
    with open(archivo_log_cifrado, "r", encoding="utf-8") as f:
        content = f.read()

    bloques = [b.strip() for b in content.split("\n\n") if b.strip()]

    for idx, bloque in enumerate(bloques, start=1):
        try:
            rec = json.loads(bloque)
            print(msj.procesando_entrada(idx))

            # Intentar descifrado híbrido (si la entrada tiene los campos híbridos que usa registrar_log_hibrido_hmac)
            texto = ""
            if all(k in rec for k in ("voto_cifrado", "iv", "tag_gcm", "clave_sim_cifrada")):
                try:
                    # probar varias firmas posibles de la función descifrado_hibrido_voto
                    try:
                        texto = descifrado_hibrido_voto(archivo_clave_priv, rec["voto_cifrado"], rec["iv"], rec["tag_gcm"], rec["clave_sim_cifrada"])
                    except TypeError:
                        # firma alternativa: clave_priv al final
                        texto = descifrado_hibrido_voto(rec["voto_cifrado"], rec["iv"], rec["tag_gcm"], rec["clave_sim_cifrada"], archivo_clave_priv)
                except Exception as e:
                    texto = f"[ERROR DESCIFRADO] {e}"
            else:
                # Fallback: intentar descifrar como registro simétrico si tiene otros nombres de campos
                try:
                    from crypto import _cargar_o_crear_clave_maestra, descifrar_de_log
                    clave = _cargar_o_crear_clave_maestra(archivo_clave_priv)
                    iv = rec.get("iv_b64") or rec.get("iv")
                    tag = rec.get("tag_b64") or rec.get("tag_gcm")
                    ct = rec.get("ct_b64") or rec.get("voto_cifrado")
                    texto = descifrar_de_log(clave, iv, tag, ct)
                except Exception as e:
                    texto = f"[ERROR DESCIFRADO] {e}"

            entrada = {
                "timestamp": rec.get("timestamp"),
                "usuario": rec.get("usuario"),
                "seleccion": rec.get("seleccion"),
                "texto": texto,
            }

            # Verificar HMAC (si existe)
            if "mac" in rec:
                try:
                    clave_mac = _cargar_o_crear_clave_mac("clave_mac_logs.bin")
                    mac_calc = hmac.new(clave_mac, texto.encode("utf-8"), hashlib.sha256)
                    mac_esperado = base64.b64decode(rec["mac"])
                    entrada["mac_verificacion"] = " VÁLIDO" if hmac.compare_digest(mac_calc.digest(), mac_esperado) else " INVÁLIDO"
                    entrada["mac_presente"] = "Si"
                except Exception as e:
                    entrada["mac_verificacion"] = f"Error: {e}"
                    entrada["mac_presente"] = "No"
            else:
                entrada["mac_verificacion"] = "Sin MAC"
                entrada["mac_presente"] = "No"

            out.append(entrada)

        except Exception as e:
            print(msj.error_entrada(idx, e))
            continue

    # Escribir salida JSONL (una entrada por línea)
    try:
        with open(salida, "w", encoding="utf-8") as g:
            for r in out:
                g.write(json.dumps(r, ensure_ascii=False) + "\n")

        print(msj.LOG_EXPORTADO_FMT.format(salida=salida))

        con_hmac = sum(1 for r in out if r.get("mac_presente") == "Si")
        if con_hmac > 0:
            print(msj.ENTRADAS_CON_HMAC_FMT.format(count=con_hmac))

    except Exception as e:
        print(msj.ERROR_ESCRIBIR_ARCHIVO_FMT.format(e=e))

    from data import msj_espera
    msj_espera.pause()

