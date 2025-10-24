# Funciones de auditoría y cifrado exactas del sistema_votacion.py original
import os
import json
import getpass
from datetime import datetime
from funciones_cripto import _cargar_o_crear_clave_maestra, cifrar_para_log, descifrar_de_log, calcular_hmac_sha512, verificar_hmac_sha512, _cargar_o_crear_clave_mac, cifrado_hibrido_voto, descifrado_hibrido_voto, crear_claves_administrador

def registrar_log_cifrado(usuario: str, seleccion: str, archivo_log_cifrado, archivo_clave):
    clave = _cargar_o_crear_clave_maestra(archivo_clave)
    mensaje = f"Voto de {usuario} para {seleccion} @ {datetime.now().isoformat(timespec='seconds')}"
    blob = cifrar_para_log(clave, mensaje)
    
    # Generar HMAC del mensaje original para autenticación
    import hmac
    import hashlib
    import base64
    clave_mac = _cargar_o_crear_clave_mac("clave_mac_logs.bin")
    mac = hmac.new(clave_mac, mensaje.encode('utf-8'), hashlib.sha256)
    mac_b64 = base64.b64encode(mac.digest()).decode()
    
    print(f"[LOG] HMAC generado con SHA-256 (clave 256 bits)")
    print(f"[LOG] Algoritmo MAC: HMAC-SHA256")
    print(f"[LOG] Longitud clave MAC: 256 bits")
    print(f"[LOG] HMAC del mensaje: {mac_b64}\n")
    
    linea = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        **blob,
        "mac_algoritmo": "HMAC-SHA256",
        "mac_longitud_clave": 256,
        "mac": mac_b64
    }
    with open(archivo_log_cifrado, "a", encoding="utf-8") as f:
        f.write(json.dumps(linea, ensure_ascii=False) + "\n")

def exportar_log_descifrado(archivo_log_cifrado, archivo_clave, salida="log_descifrado.jsonl", admin_mode=False):
    # Solicitar clave de administrador solo si no es modo admin
    if not admin_mode:
        print("\n--- ACCESO ADMINISTRATIVO ---")
        clave_admin = getpass.getpass("Ingrese clave de administrador: ")
        
        # Clave de administrador (en producción debería estar cifrada)
        if clave_admin != "admin123":
            print("Clave de administrador incorrecta.")
            input("\nPresiona Enter para continuar...")
            return
    else:
        print("\n--- ACCESO ADMINISTRATIVO AUTORIZADO ---")
    
    if not os.path.exists(archivo_log_cifrado):
        print("No hay log cifrado que exportar.")
        input("\nPresiona Enter para continuar...")
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
    
    input("\nPresiona Enter para continuar...")

# ===== FUNCIONES CON AUTENTICACIÓN MAC =====

def registrar_log_cifrado_con_mac(usuario: str, seleccion: str, archivo_log_cifrado, archivo_clave):
    """Registrar log cifrado con autenticación HMAC-SHA512"""
    # Cifrar el mensaje
    clave = _cargar_o_crear_clave_maestra(archivo_clave)
    mensaje = f"Voto de {usuario} para {seleccion} @ {datetime.now().isoformat(timespec='seconds')}"
    blob = cifrar_para_log(clave, mensaje)
    
    # Crear línea base
    linea_base = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        **blob
    }
    
    # Generar HMAC del contenido completo
    clave_mac = _cargar_o_crear_clave_mac("clave_mac_logs.bin")
    contenido_para_mac = json.dumps(linea_base, sort_keys=True, ensure_ascii=False)
    mac = calcular_hmac_sha512(clave_mac, contenido_para_mac)
    
    # Línea final con MAC
    linea_autenticada = {
        **linea_base,
        "mac_algoritmo": "HMAC-SHA512",
        "mac_longitud_clave": 256,
        "mac": mac
    }
    
    # Escribir al archivo
    with open(archivo_log_cifrado, "a", encoding="utf-8") as f:
        f.write(json.dumps(linea_autenticada, ensure_ascii=False) + "\n")
    
    print(f"[LOG] Entrada de log cifrada y autenticada guardada")

def verificar_log_mac(archivo_log_cifrado):
    """Verificar integridad de todas las entradas del log con MAC"""
    if not os.path.exists(archivo_log_cifrado):
        print("[LOG] No existe archivo de log para verificar")
        return
    
    print("\n--- VERIFICACIÓN DE INTEGRIDAD DEL LOG ---")
    clave_mac = _cargar_o_crear_clave_mac("clave_mac_logs.bin")
    
    entradas_validas = 0
    entradas_invalidas = 0
    entradas_sin_mac = 0
    
    with open(archivo_log_cifrado, "r", encoding="utf-8") as f:
        for num_linea, line in enumerate(f, 1):
            if not line.strip():
                continue
            
            try:
                rec = json.loads(line)
                
                # Verificar si tiene MAC
                if "mac" not in rec:
                    print(f"[LOG] Línea {num_linea}: Sin autenticación MAC")
                    entradas_sin_mac += 1
                    continue
                
                # Extraer MAC y reconstruir contenido original
                mac_esperado = rec["mac"]
                contenido_sin_mac = {k: v for k, v in rec.items() 
                                   if k not in ["mac", "mac_algoritmo", "mac_longitud_clave"]}
                contenido_para_verificar = json.dumps(contenido_sin_mac, sort_keys=True, ensure_ascii=False)
                
                # Verificar MAC
                if verificar_hmac_sha512(clave_mac, contenido_para_verificar, mac_esperado):
                    print(f"[LOG] Línea {num_linea}: ✓ Integridad verificada")
                    entradas_validas += 1
                else:
                    print(f"[LOG] Línea {num_linea}: ✗ INTEGRIDAD COMPROMETIDA")
                    entradas_invalidas += 1
                    
            except Exception as e:
                print(f"[LOG] Línea {num_linea}: Error al verificar - {e}")
                entradas_invalidas += 1
    
    # Resumen
    print(f"\n--- RESUMEN DE VERIFICACIÓN ---")
    print(f"✓ Entradas válidas: {entradas_validas}")
    print(f"✗ Entradas inválidas: {entradas_invalidas}")
    print(f"⚠ Entradas sin MAC: {entradas_sin_mac}")
    
    if entradas_invalidas > 0:
        print(" ADVERTENCIA: Se detectaron entradas con integridad comprometida")
    elif entradas_validas > 0:
        print(" Todas las entradas autenticadas son válidas")
    
    input("\nPresiona Enter para continuar...")

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

def exportar_log_hibrido_descifrado(archivo_log_cifrado, salida="log_descifrado.jsonl", admin_mode=False):
    """
    Descifrar log híbrido con verificación HMAC
    Funciona tanto para logs híbridos como tradicionales
    """
    import hmac
    import hashlib
    import base64
    
    # Verificación de acceso admin
    if not admin_mode:
        print("\n--- ACCESO ADMINISTRATIVO ---")
        clave_admin = getpass.getpass("Ingrese clave de administrador: ")
        if clave_admin != "admin123":
            print("Clave de administrador incorrecta.")
            input("\nPresiona Enter para continuar...")
            return
    else:
        print("\n--- ACCESO ADMINISTRATIVO AUTORIZADO ---")
    
    if not os.path.exists(archivo_log_cifrado):
        print("No hay log cifrado que exportar.")
        input("\nPresiona Enter para continuar...")
        return
    
    print("Acceso autorizado. Procesando log híbrido...")
    
    # Cargar clave privada RSA y clave HMAC
    archivo_priv = "admin_private_key.pem"
    clave_mac = _cargar_o_crear_clave_mac("clave_mac_logs.bin")
    
    out = []
    
    with open(archivo_log_cifrado, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            if not line.strip():
                continue
            
            try:
                rec = json.loads(line)
                print(f"Procesando entrada {line_num}...")
                
                # Detectar tipo de entrada (híbrida vs tradicional)
                if "clave_sim_cifrada" in rec:
                    # === ENTRADA HÍBRIDA ===
                    try:
                        # Descifrar usando cifrado híbrido
                        voto_hibrido = {
                            "voto_cifrado": rec["voto_cifrado"],
                            "iv": rec["iv"],
                            "tag": rec["tag_gcm"],
                            "clave_sim_cifrada": rec["clave_sim_cifrada"]
                        }
                        
                        mensaje_descifrado = descifrado_hibrido_voto(voto_hibrido, archivo_priv)
                        
                        # Verificar HMAC
                        if "mac" in rec:
                            mac_calculado = hmac.new(clave_mac, mensaje_descifrado.encode('utf-8'), hashlib.sha256)
                            mac_esperado = base64.b64decode(rec["mac"])
                            
                            if hmac.compare_digest(mac_calculado.digest(), mac_esperado):
                                mac_verificacion = "✓ VÁLIDO"
                            else:
                                mac_verificacion = "✗ INVÁLIDO"
                        else:
                            mac_verificacion = "Sin MAC"
                        
                        entrada = {
                            "timestamp": rec.get("timestamp"),
                            "usuario": rec.get("usuario"),
                            "seleccion": rec.get("seleccion"),
                            "mensaje_completo": mensaje_descifrado,
                            "algoritmo_simetrico": rec.get("algoritmo_simetrico"),
                            "algoritmo_asimetrico": rec.get("algoritmo_asimetrico"),
                            "mac_algoritmo": rec.get("mac_algoritmo"),
                            "mac_verificacion": mac_verificacion,
                            "tipo_cifrado": "HÍBRIDO"
                        }
                        
                    except Exception as e:
                        entrada = {
                            "timestamp": rec.get("timestamp"),
                            "error": f"Error descifrado híbrido: {e}",
                            "tipo_cifrado": "HÍBRIDO_ERROR"
                        }
                
                else:
                    # === ENTRADA TRADICIONAL ===
                    # Código existente para compatibilidad
                    try:
                        clave = _cargar_o_crear_clave_maestra("clave_aes.bin")
                        texto = descifrar_de_log(clave, rec["iv_b64"], rec["tag_b64"], rec["ct_b64"])
                    except Exception as e:
                        texto = f"[ERROR DESCIFRADO] {e}"
                    
                    entrada = {
                        "timestamp": rec.get("timestamp"),
                        "algoritmo": rec.get("algoritmo", "AES-GCM"),
                        "key_bits": rec.get("key_bits", 256),
                        "texto": texto,
                        "tipo_cifrado": "TRADICIONAL"
                    }
                
                out.append(entrada)
                
            except Exception as e:
                print(f"Error procesando línea {line_num}: {e}")
                continue
    
    # Escribir archivo de salida
    try:
        with open(salida, "w", encoding="utf-8") as g:
            for r in out:
                g.write(json.dumps(r, ensure_ascii=False) + "\n")
        
        print(f"Log descifrado exportado en: {salida}")
        print(f"Procesadas {len(out)} entradas")
        
        # Estadísticas por tipo
        hibridos = sum(1 for r in out if r.get("tipo_cifrado") == "HÍBRIDO")
        tradicionales = sum(1 for r in out if r.get("tipo_cifrado") == "TRADICIONAL")
        
        if hibridos > 0:
            print(f"{hibridos} entradas con cifrado híbrido")
        if tradicionales > 0:
            print(f"{tradicionales} entradas con cifrado tradicional")
        
    except Exception as e:
        print(f"Error escribiendo archivo: {e}")
    
    input("\nPresiona Enter para continuar...")