# Funciones de auditoría y cifrado exactas del sistema_votacion.py original
import os
import json
import getpass
from datetime import datetime
from funciones_cripto import _cargar_o_crear_clave_maestra, cifrar_para_log, descifrar_de_log

def registrar_log_cifrado(usuario: str, seleccion: str, archivo_log_cifrado, archivo_clave):
    clave = _cargar_o_crear_clave_maestra(archivo_clave)
    mensaje = f"Voto de {usuario} para {seleccion} @ {datetime.now().isoformat(timespec='seconds')}"
    blob = cifrar_para_log(clave, mensaje)
    linea = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        **blob
    }
    with open(archivo_log_cifrado, "a", encoding="utf-8") as f:
        f.write(json.dumps(linea, ensure_ascii=False) + "\n")

def exportar_log_descifrado(archivo_log_cifrado, archivo_clave, salida="log_descifrado.jsonl"):
    # Solicitar clave de administrador
    print("\n--- ACCESO ADMINISTRATIVO ---")
    clave_admin = getpass.getpass("Ingrese clave de administrador: ")
    
    # Clave de administrador (en producción debería estar cifrada)
    if clave_admin != "admin123":
        print("Clave de administrador incorrecta.")
        input("\nPresiona Enter para continuar...")
        return
    
    if not os.path.exists(archivo_log_cifrado):
        print("No hay log cifrado que exportar.")
        input("\nPresiona Enter para continuar...")
        return
        
    print("Acceso autorizado")
    clave = _cargar_o_crear_clave_maestra(archivo_clave)
    out = []
    with open(archivo_log_cifrado, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            rec = json.loads(line)
            try:
                texto = descifrar_de_log(clave, rec["iv_b64"], rec["tag_b64"], rec["ct_b64"])
            except Exception as e:
                texto = f"[ERROR DESCIFRADO] {e}"
            out.append({
                "timestamp": rec.get("timestamp"),
                "algoritmo": rec.get("algoritmo"),
                "key_bits": rec.get("key_bits"),
                "texto": texto
            })
    with open(salida, "w", encoding="utf-8") as g:
        for r in out:
            g.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"Log descifrado exportado en: {salida}")
    input("\nPresiona Enter para continuar...")