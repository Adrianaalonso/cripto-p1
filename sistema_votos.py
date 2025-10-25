# Funciones de votación exactas del sistema_votacion.py original
import json
from datetime import datetime
import uuid
from archivos_json import cargar_votos, guardar_votos
from crypto import (
    cifrado_hibrido_voto,
    crear_claves_administrador,
    calcular_hmac_sha256,
    _cargar_o_crear_clave_mac,
)


def votar(usuario_actual, opciones_votacion, archivo_votos):
    """Realizar votación"""
    votos = cargar_votos(archivo_votos)
    
    # Verificar si ya votó
    if usuario_actual in votos["usuarios_votaron"]:
        print("Ya has votado anteriormente. No puedes votar nuevamente.")
        # Mostrar pausa estándar para que el usuario vea el mensaje antes de continuar
        from data import msj_ui
        msj_ui.pause()
        return None
    
    print("\n--- OPCIONES DE VOTACIÓN ---")
    print("📦 1. Opción A")
    print("📦 2. Opción B")
    print("0. Cancelar")
    
    try:
        opcion = int(input("\nSeleccione su opción (1 o 2): "))
        if opcion not in (0, 1, 2):
            print("Opción no válida.")
            return None
        if opcion == 0:
            print("Votación cancelada.")
            return None
        # Registrar voto
        seleccion = opciones_votacion[opcion - 1]
        
        # ===== CIFRADO HÍBRIDO + HMAC DEL VOTO (ANÓNIMO) =====
        # Crear claves RSA del administrador si no existen
        archivo_priv, archivo_pub = crear_claves_administrador()
        
        # Generar timestamp con precisión a minutos y un ID aleatorio por voto (no identifica al usuario)
        ts = datetime.now().replace(second=0, microsecond=0).isoformat()
        vote_id = uuid.uuid4().hex       

        # Cifrar SOLO la selección (manteniendo anonimato)
        print(f"\nAplicando cifrado híbrido anónimo al voto: {seleccion}")
        voto_cifrado_hibrido = cifrado_hibrido_voto(seleccion, archivo_pub)
        
        # Generar HMAC sobre los campos que vamos a guardar
        clave_mac = _cargar_o_crear_clave_mac("clave_mac_logs.bin")
        mac_obj = {
            "vote_id": vote_id,
            "voto_cifrado": voto_cifrado_hibrido["voto_cifrado"],
            "iv": voto_cifrado_hibrido["iv"],
            "tag": voto_cifrado_hibrido["tag"],
            "clave_sim_cifrada": voto_cifrado_hibrido["clave_sim_cifrada"],
            "timestamp": ts
        }
        contenido_para_mac = json.dumps(mac_obj, sort_keys=True, separators=(',',':'), ensure_ascii=False)
        mac_b64 = calcular_hmac_sha256(clave_mac, contenido_para_mac)
        
        print(f"HMAC-SHA256 generado para integridad")
        
        # Guardar SOLO datos cifrados (SIN usuario, SIN mensaje_completo)
        archivo_votos_cifrados = "votos_cifrados.jsonl"
        linea_voto = {
            "vote_id" : vote_id,
            "timestamp": ts,
            **voto_cifrado_hibrido,
            # Información HMAC (para verificación)
            "mac_algoritmo": "HMAC-SHA256",
            "mac_longitud_clave": 256,
            "mac": mac_b64
            # No incluimos usuario para mantener el anonimato
        }
        
        with open(archivo_votos_cifrados, "a", encoding="utf-8") as f:
            f.write(json.dumps(linea_voto, ensure_ascii=False) + "\n")
        
        print(f"Voto anónimo cifrado híbrido + HMAC guardado en: {archivo_votos_cifrados}")
        
        # Mantener el conteo normal para resultados públicos
        votos[seleccion] += 1
        votos["usuarios_votaron"].append(usuario_actual)
        guardar_votos(votos, archivo_votos)
        print(f"Voto registrado para: {seleccion}")
        return seleccion
            
    except ValueError:
        print("Por favor ingrese un número válido.")
        return None

def mostrar_resultados(archivo_votos):
    """Mostrar resultados de la votación"""
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