# Funciones de archivos JSON exactas del sistema_votacion.py original
import os
import json
from crypto import calcular_hmac_sha256, verificar_hmac_sha256, cargar_o_crear_clave_mac

def cargar_usuarios(archivo_usuarios):
    """Cargar usuarios desde el archivo JSON"""
    if os.path.exists(archivo_usuarios):
        with open(archivo_usuarios, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def guardar_usuarios(usuarios, archivo_usuarios):
    """Guardar usuarios en el archivo JSON"""
    with open(archivo_usuarios, 'w', encoding='utf-8') as f:
        json.dump(usuarios, f, indent=2, ensure_ascii=False)

def cargar_votos(archivo_votos):
    """Cargar votos desde el archivo JSON"""
    defaults = {"Opción A": 0, "Opción B": 0, "usuarios_votaron": []}
    if os.path.exists(archivo_votos):
        try:
            with open(archivo_votos, 'r', encoding='utf-8') as f:
                v = json.load(f)
            # Rellenar claves faltantes
            for k, val in defaults.items():
                v.setdefault(k, val if not isinstance(val, list) else list(val))
            return v
        except Exception:
            return defaults.copy()
    return defaults.copy()
    
def guardar_votos(votos, archivo_votos):
    """Guardar votos en el archivo JSON"""
    with open(archivo_votos, 'w', encoding='utf-8') as f:
        json.dump(votos, f, indent=2, ensure_ascii=False)

# ===== FUNCIONES CON AUTENTICACIÓN MAC =====

def guardar_usuarios_con_mac(usuarios, archivo_usuarios):
    """Guardar usuarios con autenticación HMAC-SHA256"""
    # Generar contenido JSON
    contenido_json = json.dumps(usuarios, indent=2, ensure_ascii=False)
    
    # Cargar clave MAC
    clave_mac = cargar_o_crear_clave_mac("json/clave_mac_usuarios.bin")
    
    # Calcular HMAC del contenido
    mac = calcular_hmac_sha256(clave_mac, contenido_json)
    
    # Crear estructura autenticada
    estructura_autenticada = {
        "algoritmo_mac": "HMAC-SHA256",
        "longitud_clave": 256,
        "contenido": usuarios,
        "mac": mac
    }
    
    # Guardar archivo autenticado
    with open(archivo_usuarios, 'w', encoding='utf-8') as f:
        json.dump(estructura_autenticada, f, indent=2, ensure_ascii=False)
    
    print(f"[LOG] Archivo {archivo_usuarios} guardado con autenticación HMAC-SHA256")

def cargar_usuarios_con_mac(archivo_usuarios):
    """Cargar usuarios verificando autenticación HMAC-SHA256"""
    if not os.path.exists(archivo_usuarios):
        return {}
    
    try:
        with open(archivo_usuarios, 'r', encoding='utf-8') as f:
            estructura = json.load(f)
        
        # Verificar si tiene estructura autenticada
        if "mac" not in estructura or "contenido" not in estructura:
            print("[LOG] Archivo sin autenticación MAC, cargando sin verificar")
            return estructura
        
        # Cargar clave MAC
        clave_mac = cargar_o_crear_clave_mac("json/clave_mac_usuarios.bin")

        # Reconstruir contenido original para verificar
        contenido_json = json.dumps(estructura["contenido"], indent=2, ensure_ascii=False)
        
        # Verificar HMAC
        if verificar_hmac_sha256(clave_mac, contenido_json, estructura["mac"]):
            print(f"[LOG] ✓ Integridad de {archivo_usuarios} verificada correctamente")
            return estructura["contenido"]
        else:
            print(f"[LOG] ✗ ADVERTENCIA: Integridad de {archivo_usuarios} COMPROMETIDA")
            print("[LOG] El archivo puede haber sido modificado maliciosamente")
            return {}
    
    except Exception as e:
        print(f"[LOG] Error al cargar {archivo_usuarios}: {e}")
        return {}

def guardar_votos_con_mac(votos, archivo_votos):
    """Guardar votos con autenticación HMAC-SHA256"""
    # Generar contenido JSON
    contenido_json = json.dumps(votos, indent=2, ensure_ascii=False)
    
    # Cargar clave MAC
    clave_mac = cargar_o_crear_clave_mac("json/clave_mac_votos.bin")
    
    # Calcular HMAC del contenido
    mac = calcular_hmac_sha256(clave_mac, contenido_json)
    
    # Crear estructura autenticada
    estructura_autenticada = {
        "algoritmo_mac": "HMAC-SHA256",
        "longitud_clave": 256,
        "contenido": votos,
        "mac": mac
    }
    
    # Guardar archivo autenticado
    with open(archivo_votos, 'w', encoding='utf-8') as f:
        json.dump(estructura_autenticada, f, indent=2, ensure_ascii=False)
    
    print(f"[LOG] Archivo {archivo_votos} guardado con autenticación HMAC-SHA256")

def cargar_votos_con_mac(archivo_votos):
    """Cargar votos verificando autenticación HMAC-SHA256"""
    defaults = {"Opción A": 0, "Opción B": 0, "usuarios_votaron": []}
    
    if not os.path.exists(archivo_votos):
        return defaults.copy()
    
    try:
        with open(archivo_votos, 'r', encoding='utf-8') as f:
            estructura = json.load(f)
        
        # Verificar si tiene estructura autenticada
        if "mac" not in estructura or "contenido" not in estructura:
            print("[LOG] Archivo sin autenticación MAC, cargando sin verificar")
            # Rellenar claves faltantes para compatibilidad
            v = estructura
            for k, val in defaults.items():
                v.setdefault(k, val if not isinstance(val, list) else list(val))
            return v
        
        # Cargar clave MAC
        clave_mac = cargar_o_crear_clave_mac("json/clave_mac_votos.bin")

        # Reconstruir contenido original para verificar
        contenido_json = json.dumps(estructura["contenido"], indent=2, ensure_ascii=False)
        
        # Verificar HMAC
        if verificar_hmac_sha256(clave_mac, contenido_json, estructura["mac"]):
            print(f"[LOG] ✓ Integridad de {archivo_votos} verificada correctamente")
            votos = estructura["contenido"]
            # Rellenar claves faltantes
            for k, val in defaults.items():
                votos.setdefault(k, val if not isinstance(val, list) else list(val))
            return votos
        else:
            print(f"[LOG] ✗ ADVERTENCIA: Integridad de {archivo_votos} COMPROMETIDA")
            print("[LOG] El archivo puede haber sido modificado maliciosamente")
            return defaults.copy()
    
    except Exception as e:
        print(f"[LOG] Error al cargar {archivo_votos}: {e}")
        return defaults.copy()