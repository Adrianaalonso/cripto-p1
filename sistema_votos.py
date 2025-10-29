# Funciones de votación exactas del sistema_votacion.py original
import json
import os
from datetime import datetime
import uuid
from archivos_json import cargar_votos, guardar_votos
from crypto import (
    cifrado_hibrido_voto,
    crear_claves_administrador,
    calcular_hmac_sha256,
    cargar_o_crear_clave_mac,
)
from data import msj_comunes as msj
from data import msj_espera

def votar(usuario_actual, opciones_votacion, archivo_votos):
    """funcion para votar"""
    votos = cargar_votos(archivo_votos)
    
    #verificamos si el usuario ya ha vptado
    if usuario_actual in votos["usuarios_votaron"]:
        print(msj.YA_VOTASTE)
        #pausa para que el usuario vea el mensaje antes de continuar
        msj_espera.pause()
        return None
    
    print("\n" + msj.OPCIONES_VOTACION)
    print("📦 1. Opción A")
    print("📦 2. Opción B")
    print(msj.VOTO_CANCELAR)
    
    try:
        opcion = int(input(msj.PROMPT_SELECCION_VOTO))
        if opcion not in (0, 1, 2):
            print(msj.OPCION_INVALIDA)
            return None
        if opcion == 0:
            print("Votación cancelada.")
            return None
        # Registrar voto
        seleccion = opciones_votacion[opcion - 1]
        
        # ===== CIFRADO HÍBRIDO + HMAC DEL VOTO =====
        # creamos claves RSA del administrador si no existen
        archivo_priv, archivo_pub = crear_claves_administrador()
        
        #generamos timestamp con precisión a minutos y no segundos para que no haya tanta exactitud, menos trazabilidad
        #ID aleatorio por voto, el usuario se mantiene anónimo
        ts = datetime.now().replace(second=0, microsecond=0).isoformat()
        vote_id = uuid.uuid4().hex       

        #ciframos la selección, no incluimos informacion del usuario
        print(msj.CIFRADO_HIBRIDO_FMT.format(seleccion=seleccion))
        print()
        voto_cifrado_hibrido = cifrado_hibrido_voto(seleccion, archivo_pub)

        #generamos HMAC sobre los campos que vamos a guardar en el json cifrado
        clave_mac = cargar_o_crear_clave_mac("json/clave_mac_logs.bin")
        mac_obj = {
            "vote_id": vote_id,
            "voto_cifrado": voto_cifrado_hibrido["voto_cifrado"],
            "iv": voto_cifrado_hibrido["iv"],
            "tag": voto_cifrado_hibrido["tag"],
            "clave_sim_cifrada": voto_cifrado_hibrido["clave_sim_cifrada"],
            "timestamp": ts
        }
        contenido_para_mac = json.dumps(mac_obj, sort_keys=True, separators=(',',':'), ensure_ascii=False)
        #calculamos HMAC-sha256 del contenido anterior usando la clave y lo codificamos en base 64
        mac_b64 = calcular_hmac_sha256(clave_mac, contenido_para_mac)
        print(msj.HMAC_OK)

        print()

        # Guardamos datos cifrados manteniendo el anonimato
        archivo_votos_cifrados = "json/votos_cifrados.jsonl"
        linea_voto = {
            "vote_id" : vote_id,
            "timestamp": ts,
            **voto_cifrado_hibrido,
            # Información HMAC (para verificación)
            "mac_algoritmo": "HMAC-SHA256",
            "mac_longitud_clave": 256,
            "mac": mac_b64
        }

        # Aseguramos que existe carpeta json/
        try:
            os.makedirs("json", exist_ok=True)
        except Exception:
            pass

        #optamos por escribir en formato jsonl (una línea por voto) para facilitar el procesamiento posterior
        with open(archivo_votos_cifrados, "a", encoding="utf-8") as f:
            f.write(json.dumps(linea_voto, ensure_ascii=False) + "\n")
        print(msj.VOTO_GUARDADO_FMT.format(path=archivo_votos_cifrados))

        #conteo para resultados
        votos[seleccion] += 1
        votos["usuarios_votaron"].append(usuario_actual)
        guardar_votos(votos, archivo_votos)
        print(msj.VOTO_REGISTRADO_FMT.format(opcion=seleccion))
        return seleccion
            
    except ValueError:
        print("Por favor ingrese un número válido.")
        return None

def mostrar_resultados(archivo_votos):
    """mostrar resultados de los votos (conteo)"""
    votos = cargar_votos(archivo_votos)
    total_votos = votos["Opción A"] + votos["Opción B"]
    
    print("\n" + "="*40)
    print("   RESULTADOS DE VOTACIÓN")
    print("="*40)
    
    if total_votos > 0:
        print(f"📦 Opción A: {votos['Opción A']} votos ({votos['Opción A']/total_votos*100:.1f}%)")
        print(f"📦 Opción B: {votos['Opción B']} votos ({votos['Opción B']/total_votos*100:.1f}%)")
        print(f"\nTotal de votos: {total_votos}")
    else:
        print(" No hay votos registrados aún.")
    
    print("="*40)
    from data import msj_espera
    msj_espera.pause()