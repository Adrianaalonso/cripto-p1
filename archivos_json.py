# Funciones de archivos JSON exactas del sistema_votacion.py original
import os
import json

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