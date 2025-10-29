# Menú y funciones específicas para administradores
from crypto import (
    descifrado_hibrido_voto,
    cargar_o_crear_clave_mac,
    verificar_hmac_sha256,
)
import json
import os
from data import msj_comunes as msj

def mostrar_menu_admin():
    """Mostrar menú de opciones para administradores"""
    print("\n" + msj.ADMIN_MENU_LINE)
    print(msj.ADMIN_PANEL_TITLE)
    print(msj.ADMIN_MENU_LINE)
    print(msj.ADMIN_OP_DESCIFRAR)
    print(msj.ADMIN_OP_CERRAR)
    print(msj.ADMIN_MENU_LINE)

def ejecutar_panel_admin(usuario_admin):
    """Ejecutar panel de administrador"""
    print(f"\n Acceso de administrador: {usuario_admin}")
    while True:
        mostrar_menu_admin()
        try:
            opcion = input(msj.PROMPT_SELECCIONAR)
            if opcion == "1":
                print("\n=== DESCIFRADO DE VOTOS HÍBRIDOS + HMAC ===")
                descifrar_votos_hibridos_con_hmac()  
            elif opcion == "2":
                print(f" Cerrando sesión de administrador: {usuario_admin}")
                break 
            else:
                print(msj.OPCION_INVALIDA)    
        except KeyboardInterrupt:
            print(f"\n Cerrando sesión de administrador: {usuario_admin}")
            break
    return None

def descifrar_votos_hibridos_con_hmac():
    """Descifrar votos con cifrado híbrido+HMAC"""
    archivo_votos_cifrados = "votos_cifrados.jsonl"
    archivo_clave_privada = "admin_private_key.pem"
    
    if not os.path.exists(archivo_votos_cifrados):
        print(msj.NO_VOTES_CIPHERED)
        from data import msj_espera
        msj_espera.pause()
        return
    
    if not os.path.exists(archivo_clave_privada):
        print(msj.NO_PRIVATE_KEY)
        from data import msj_espera
        msj_espera.pause()
        return
    print("Descifrado de votos híbridos anónimos...")
    
    # Cargar clave HMAC
    clave_mac = cargar_o_crear_clave_mac("clave_mac_logs.bin")
    #comprobamos la integridad de la estructura almacenada, si el HMAC coincide, el fichero no ha sido alterado
    votos_descifrados = []
    try:
        with open(archivo_votos_cifrados, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                if not line.strip():
                    continue
                
                try:
                    voto_cifrado = json.loads(line)
                    print(msj.procesando_entrada(line_num))
                    
                    # Descifrar usando cifrado híbrido
                    voto_hibrido = {
                        "voto_cifrado": voto_cifrado["voto_cifrado"],
                        "iv": voto_cifrado["iv"],
                        "tag": voto_cifrado["tag"],
                        "clave_sim_cifrada": voto_cifrado["clave_sim_cifrada"]
                    }
                    
                    try:
                        seleccion_descifrada = descifrado_hibrido_voto(voto_hibrido, archivo_clave_privada)
                    except Exception as e:
                        seleccion_descifrada = f"[ERROR DESCIFRADO] {e}"
                    
                    # Verificar HMAC reconstruyendo la misma estructura usada al crear el voto en sistema_votos, 
                    # para comprobar que la estructura es la original
                    mac_verificacion = "No verificable (voto anónimo)"
                    if "mac" in voto_cifrado:
                        try:
                            mac_obj = {
                                "vote_id": voto_cifrado.get("vote_id",""),
                                "voto_cifrado": voto_cifrado.get("voto_cifrado",""),
                                "iv": voto_cifrado.get("iv",""),
                                "tag": voto_cifrado.get("tag",""),
                                "clave_sim_cifrada": voto_cifrado.get("clave_sim_cifrada",""),
                                "timestamp": voto_cifrado.get("timestamp","")
                            }
                            contenido_para_mac = json.dumps(mac_obj, sort_keys=True, separators=(',',':'), ensure_ascii=False)
                            valido = verificar_hmac_sha256(clave_mac, contenido_para_mac, voto_cifrado["mac"])
                            mac_verificacion = "HMAC válido" if valido else "HMAC inválido"
                        except Exception as e:
                            mac_verificacion = f"HMAC verif. error: {e}"
                    
                    resultado = {
                        "vote_id": voto_cifrado.get("vote_id"),
                        "timestamp": voto_cifrado.get("timestamp", "N/A"),
                        "voto_descifrado": seleccion_descifrada,
                        "algoritmo_simetrico": voto_cifrado.get("algoritmo_simetrico", "AES-GCM-256"),
                        "algoritmo_asimetrico": voto_cifrado.get("algoritmo_asimetrico", "RSA-2048-OAEP"),
                        "mac_algoritmo": voto_cifrado.get("mac_algoritmo", "N/A"),
                        "mac_verificacion": mac_verificacion
                    }
                    
                    votos_descifrados.append(resultado)
                except Exception as e:
                    print(msj.error_entrada(line_num, e))
                    
                    continue
        
        # Guardar votos descifrados
        archivo_salida = "votos_descifrados.json"
        with open(archivo_salida, "w", encoding="utf-8") as f:
            json.dump(votos_descifrados, f, ensure_ascii=False, indent=2)
        
        print(f"\n Descifrado completo:")
        print(f" {len(votos_descifrados)} votos anónimos descifrados exitosamente")
        print(f" Guardado en: {archivo_salida}")
        
        # Mostrar resumen ANÓNIMO
        if votos_descifrados:
            print("\nResumen de votos anónimos:")
            for i, voto in enumerate(votos_descifrados, 1):
                print(f"  • Voto #{i}: {voto['voto_descifrado']} ({voto['timestamp']})")
        
        # Estadísticas: contamos el num de HMAC válidos / inválidos
        con_hmac_validos = sum(1 for v in votos_descifrados if v.get('mac_verificacion') == "HMAC válido")
        con_hmac_invalidos = sum(1 for v in votos_descifrados if v.get('mac_verificacion') == "HMAC inválido")
        if con_hmac_validos > 0:
            print(f"\n {con_hmac_validos} votos con HMAC válidos")
        if con_hmac_invalidos > 0:
            print(f"\n {con_hmac_invalidos} votos con HMAC inválidos (posible manipulación)")
        
    except Exception as e:
        print(f" Error durante el descifrado: {e}")
    
    from data import msj_espera
    msj_espera.pause()