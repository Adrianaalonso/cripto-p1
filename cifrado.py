# Funciones de auditoría y cifrado exactas del sistema_votacion.py original
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

def exportar_log_descifrado(archivo_log_cifrado, archivo_clave, salida="log_descifrado.jsonl", admin_mode=False):
    # Solicitar clave de administrador solo si no es modo admin
    if not admin_mode:
        print("\n--- ACCESO ADMINISTRATIVO ---")
        clave_admin = getpass.getpass("Ingrese clave de administrador: ")
        
        # Clave de administrador (en producción debería estar cifrada)
        if clave_admin != "admin123":
            print("Clave de administrador incorrecta.")
            from data import msj_espera
            msj_espera.pause()
            return
    else:
        print("\n--- ACCESO ADMINISTRATIVO AUTORIZADO ---")
    
    if not os.path.exists(archivo_log_cifrado):
        print("No hay log cifrado que exportar.")
        from data import msj_espera
        msj_espera.pause()
        return
        
    print("Acceso autorizado. Procesando log...")
    clave = _cargar_o_crear_clave_maestra(archivo_clave)
    out = []
    
    with open(archivo_log_cifrado, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            if not line.strip():
                continue
            
            try:
                rec = json.loads(line)
                print(f"Procesando entrada {line_num}...")
                
                # Descifrar el mensaje
                try:
                    texto = descifrar_de_log(clave, rec["iv_b64"], rec["tag_b64"], rec["ct_b64"])
                except Exception as e:
                    texto = f"[ERROR DESCIFRADO] {e}"
                
                # Crear entrada básica
                entrada = {
                    "timestamp": rec.get("timestamp"),
                    "algoritmo": rec.get("algoritmo"),
                    "key_bits": rec.get("key_bits"),
                    "texto": texto
                }
                
                # Si tiene información HMAC, agregarla y verificar
                if "mac_algoritmo" in rec:
                    entrada["mac_algoritmo"] = rec.get("mac_algoritmo")
                    entrada["mac_longitud_clave"] = rec.get("mac_longitud_clave")
                    
                    # Verificar HMAC usando el texto descifrado
                    if "mac" in rec:
                        try:
                            import hmac
                            import hashlib
                            import base64
                            
                            # Cargar clave MAC
                            clave_mac = _cargar_o_crear_clave_mac("clave_mac_logs.bin")
                            
                            # Verificar HMAC con el texto descifrado
                            mac_calculado = hmac.new(clave_mac, texto.encode('utf-8'), hashlib.sha256)
                            mac_esperado = base64.b64decode(rec["mac"])
                            
                            if hmac.compare_digest(mac_calculado.digest(), mac_esperado):
                                entrada["mac_verificacion"] = "✓ VÁLIDO"
                            else:
                                entrada["mac_verificacion"] = "✗ INVÁLIDO"
                                
                        except Exception as e:
                            entrada["mac_verificacion"] = f"Error: {e}"
                    else:
                        entrada["mac_verificacion"] = "Sin MAC"
                
                out.append(entrada)
                
            except Exception as e:
                print(f"Error procesando línea {line_num}: {e}")
                continue
    
    # Escribir archivo de salida
    try:
        with open(salida, "w", encoding="utf-8") as g:
            for r in out:
                g.write(json.dumps(r, ensure_ascii=False) + "\n")
        
        print(f" Log descifrado exportado en: {salida}")
        print(f" Procesadas {len(out)} entradas")
        
        # Contar entradas con HMAC
        con_hmac = sum(1 for r in out if r.get("mac_presente") == "Si")
        if con_hmac > 0:
            print(f" {con_hmac} entradas incluyen información HMAC")
        
    except Exception as e:
        print(f" Error escribiendo archivo: {e}")
    
    from data import msj_espera
    msj_espera.pause()

# ===== CIFRADO HÍBRIDO + HMAC UNIFICADO =====

def registrar_log_hibrido_hmac(usuario: str, seleccion: str, archivo_log_cifrado):
    """
    Registrar log con cifrado híbrido (RSA+AES-GCM) + HMAC unificado
    Reemplaza tanto el log tradicional como los votos cifrados separados
    """
    import hmac
    import hashlib
    import base64
    
    # 1. Crear claves RSA si no existen
    archivo_priv, archivo_pub = crear_claves_administrador()
    
    # 2. Preparar mensaje del voto
    mensaje = f"Voto de {usuario} para {seleccion} @ {datetime.now().isoformat(timespec='seconds')}"
    
    print(f"[LOG HÍBRIDO] Cifrando voto: {seleccion}")
    
    # 3. Cifrado híbrido del mensaje
    voto_cifrado_hibrido = cifrado_hibrido_voto(mensaje, archivo_pub)
    
    # 4. Generar HMAC del mensaje original
    clave_mac = _cargar_o_crear_clave_mac("clave_mac_logs.bin")
    mac = hmac.new(clave_mac, mensaje.encode('utf-8'), hashlib.sha256)
    mac_b64 = base64.b64encode(mac.digest()).decode()
    
    # 5. Estructura unificada: Híbrido + HMAC
    linea_unificada = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
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
        "mac": mac_b64
    }
    
    # 6. Guardar en archivo log unificado
    with open(archivo_log_cifrado, "a", encoding="utf-8") as f:
        f.write(json.dumps(linea_unificada, ensure_ascii=False) + "\n")
    
    print(f"[LOG HÍBRIDO] Voto cifrado con AES-GCM-256 + RSA-2048")
    print(f"[LOG HÍBRIDO] HMAC-SHA256 generado para integridad")
    print(f"[LOG HÍBRIDO] Guardado en: {archivo_log_cifrado}")

