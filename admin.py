# Menú y funciones específicas para administradores
from crypto import (
    descifrado_hibrido_voto,
    cargar_o_crear_clave_mac,
    verificar_hmac_sha256,
)
from crypto.signature_rsa import verificar
import json
import os
from data import msj_comunes as msj
from archivos_json import cargar_usuarios
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

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
    archivo_votos_cifrados = "json/votos/votos_cifrados.jsonl"
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
    
    # Cargar clave HMAC (clave en json/logs/)
    clave_mac = cargar_o_crear_clave_mac("json/logs/clave_mac_logs.bin")
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
                    
                    # Descifrar usando cifrado híbrido (aceptamos "tag" o "tag_gcm" por compatibilidad)
                    tag_val = voto_cifrado.get("tag", voto_cifrado.get("tag_gcm"))
                    voto_hibrido = {
                        "voto_cifrado": voto_cifrado.get("voto_cifrado"),
                        "iv": voto_cifrado.get("iv"),
                        "tag": tag_val,
                        "clave_sim_cifrada": voto_cifrado.get("clave_sim_cifrada")
                    }
                    
                    try:
                        seleccion_descifrada = descifrado_hibrido_voto(voto_hibrido, archivo_clave_privada)
                    except Exception as e:
                        seleccion_descifrada = f"[ERROR DESCIFRADO] {e}"
                    
                    # Verificar HMAC reconstruyendo la misma estructura usada al crear el voto en sistema_votos, 
                    # para comprobar que la estructura es la original
                    mac_verificacion = "No verificable (voto anónimo)"
                    user_sig_verificacion = "No verificable"
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
                            # Verificar firma del usuario si está presente
                            if "user_sig" in voto_cifrado and voto_cifrado.get("user_sig"):
                                try:
                                    usuarios_reg = cargar_usuarios("json/usuarios.json")
                                    usuario_nombre = voto_cifrado.get("usuario")
                                    if usuario_nombre in usuarios_reg and usuarios_reg[usuario_nombre].get("public_key_pem"):
                                        pub_pem_str = usuarios_reg[usuario_nombre].get("public_key_pem")
                                        pub_obj = serialization.load_pem_public_key(pub_pem_str.encode('utf-8'), backend=default_backend())
                                        contenido_para_firma = json.dumps(mac_obj, sort_keys=True, separators=(',',':'), ensure_ascii=False).encode('utf-8')
                                        ok_user = verificar(pub_obj, contenido_para_firma, voto_cifrado.get("user_sig"))
                                        user_sig_verificacion = "Firma usuario válida" if ok_user else "Firma usuario inválida"
                                    else:
                                        user_sig_verificacion = "Clave pública de usuario no encontrada"
                                except Exception as e:
                                    user_sig_verificacion = f"Error verif. firma usuario: {e}"
                        except Exception as e:
                            mac_verificacion = f"HMAC verif. error: {e}"

                    
                    resultado = {
                        "vote_id": voto_cifrado.get("vote_id"),
                        "timestamp": voto_cifrado.get("timestamp", "N/A"),
                        "voto_descifrado": seleccion_descifrada,
                        "algoritmo_simetrico": voto_cifrado.get("algoritmo_simetrico", "AES-GCM-256"),
                        "algoritmo_asimetrico": voto_cifrado.get("algoritmo_asimetrico", "RSA-2048-OAEP"),
                        "mac_algoritmo": voto_cifrado.get("mac_algoritmo", "N/A"),
                        "mac_verificacion": mac_verificacion,
                        "user_sig_verificacion": user_sig_verificacion,
                    }
                    
                    votos_descifrados.append(resultado)
                except Exception as e:
                    print(msj.error_entrada(line_num, e))
                    
                    continue
        
        # Guardar votos descifrados (en carpeta votos)
        archivo_salida = "json/votos/votos_descifrados.json"
        try:
            os.makedirs(os.path.dirname(archivo_salida), exist_ok=True)
        except Exception:
            pass
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