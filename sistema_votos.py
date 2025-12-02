# Funciones de votación exactas del sistema_votacion.py original
import json
import os
from datetime import datetime
import uuid
from archivos_json import cargar_votos, guardar_votos, cargar_usuarios, guardar_usuarios
from crypto import (
    cifrado_hibrido_voto,
    crear_claves_administrador,
    calcular_hmac_sha256,
    cargar_o_crear_clave_mac,
    verificar_hmac_sha256,
)
from cifrado import registrar_log_hibrido_hmac
from data import msj_comunes as msj
from data import msj_espera
from crypto.signature_rsa import generar_par_claves_rsa, guardar_clave_privada, guardar_clave_publica
from crypto.pki import asegurar_pki, emitir_certificado_usuario, verificar_cadena_certificado, revocar_certificado
from crypto.pki import exportar_usuario_a_pfx
import getpass
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
from crypto.signature_rsa import verificar

def votar(usuario_actual, opciones_votacion, archivo_votos):
    """funcion para votar"""
    votos = cargar_votos(archivo_votos)
    
    # verificamos si el usuario ya ha votado
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
    except ValueError:
        print("Por favor ingrese un número válido.")
        return None

    if opcion not in (0, 1, 2):
        print(msj.OPCION_INVALIDA)
        return None
    if opcion == 0:
        print("Votación cancelada.")
        return None

    # Registrar voto
    seleccion = opciones_votacion[opcion - 1]

    # Antes de registrar, comprobar si el usuario ya tiene una clave en formato PFX (generada en el registro)
    os.makedirs("json/user_keys", exist_ok=True)
    usuarios_reg = cargar_usuarios('json/usuarios.json')
    user_entry = usuarios_reg.get(usuario_actual, {})
    pfx_path = user_entry.get('pfx_path')
    pem_pub_path = f"json/user_keys/{usuario_actual}_public.pem"

    if pfx_path and os.path.exists(pfx_path):
        # El usuario ya creó su PFX en el registro: no solicitar generación aquí
        pass
    else:
        # Si no existe PFX ni PEM público, ofrecer firmar el voto generando par RSA
        if not os.path.exists(pem_pub_path):
            try:
                generar = input("¿Desea generar ahora un par RSA para firmar sus votos? (s/n): ").strip().lower()
            except Exception:
                generar = 'n'
            if generar == 's':
                try:
                    priv_pem, pub_pem = generar_par_claves_rsa(bits=2048)
                    private_key_obj = serialization.load_pem_private_key(priv_pem, password=None, backend=default_backend())
                    pub_path = pem_pub_path
                    try:
                        guardar_clave_publica(pub_path, pub_pem)
                    except Exception:
                        with open(pub_path, 'wb') as f:
                            f.write(pub_pem)

                    try:
                        usuarios_reg = cargar_usuarios('json/usuarios.json')
                        usuarios_reg[usuario_actual]['public_key_pem'] = pub_pem.decode('utf-8')
                        # Emitir certificado X.509 para la clave pública del usuario
                        try:
                            asegurar_pki()
                            ruta_cert, serial = emitir_certificado_usuario(usuario_actual, pub_pem)
                            usuarios_reg[usuario_actual]['cert_path'] = ruta_cert
                            usuarios_reg[usuario_actual]['cert_serial'] = str(serial)
                            print(f"Certificado de usuario emitido y guardado en: {ruta_cert}")
                            # Usar la passphrase registrada durante el registro si existe,
                            # si no, pedirla ahora.
                            passwd = None
                            try:
                                usuarios_reg = cargar_usuarios('json/usuarios.json')
                                passwd = usuarios_reg.get(usuario_actual, {}).get('pfx_passphrase')
                            except Exception:
                                passwd = None

                            if not passwd or len(passwd) < 12:
                                # Pedir passphrase al usuario 
                                while True:
                                    try:
                                        passwd = getpass.getpass('Ingrese una passphrase para proteger su PFX (mínimo 12 caracteres): ')
                                    except Exception:
                                        passwd = ''
                                    if len(passwd) < 12:
                                        print('La passphrase debe tener al menos 12 caracteres.')
                                        continue
                                    try:
                                        confirm = getpass.getpass('Confirme la passphrase: ')
                                    except Exception:
                                        confirm = ''
                                    if passwd != confirm:
                                        print('Las passphrases no coinciden. Intente de nuevo.')
                                        continue
                                    break

                            # Exportar a PFX y guardar en json/user_keys/
                            pfx_path = exportar_usuario_a_pfx(usuario_actual, private_key_obj, ruta_cert, passwd)
                            usuarios_reg[usuario_actual]['pfx_path'] = pfx_path
                            print(f"PFX creado y almacenado en servidor: {pfx_path} (puede descargarlo en el registro).")
                        except Exception as ee:
                            print(f"Advertencia: no se pudo emitir certificado o crear PFX: {ee}")
                        guardar_usuarios(usuarios_reg, 'json/usuarios.json')
                    except Exception:
                        pass
                    print(f"Par RSA generado. Clave privada protegida en PFX y pública guardada para {usuario_actual}.")
                except Exception as e:
                    print(f"Error generando claves RSA: {e}")

    # Registrar voto 
    archivo_votos_cifrados = "json/votos/votos_cifrados.jsonl"
    success = registrar_log_hibrido_hmac(usuario_actual, seleccion, archivo_votos_cifrados)

    if not success:
        print("No se pudo registrar el voto en el log híbrido. El voto NO será contabilizado.")
        return None 
    votos[seleccion] += 1
    votos["usuarios_votaron"].append(usuario_actual)
    guardar_votos(votos, archivo_votos)
    print(msj.VOTO_REGISTRADO_FMT.format(opcion=seleccion))
    return seleccion

def mostrar_resultados(archivo_votos):
    """mostrar resultados de los votos registrados"""
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


def solicitar_verificacion(usuario_actual):
    """Permite al usuario solicitar la verificación de la firma de su voto."""
    archivo_votos_cifrados = "json/votos/votos_cifrados.jsonl"
    if not os.path.exists(archivo_votos_cifrados):
        print("No hay votos registrados todavía.")
        return

    ultima_entrada = None
    with open(archivo_votos_cifrados, 'r', encoding='utf-8') as f:
        for line in f:
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if rec.get('usuario') == usuario_actual:
                ultima_entrada = rec

    if ultima_entrada is None:
        print("No se encontró ningún voto asociado a su usuario.")
        return

    #  HMAC
    mac_obj = {
        "vote_id": ultima_entrada.get("vote_id", ""),
        "voto_cifrado": ultima_entrada.get("voto_cifrado", ""),
        "iv": ultima_entrada.get("iv", ""),
        "tag": ultima_entrada.get("tag", ""),
        "clave_sim_cifrada": ultima_entrada.get("clave_sim_cifrada", ""),
        "timestamp": ultima_entrada.get("timestamp", ""),
    }
    contenido_para_firma = json.dumps(mac_obj, sort_keys=True, separators=(',',':'), ensure_ascii=False).encode('utf-8')

    # Verificar HMAC 
    clave_mac = cargar_o_crear_clave_mac("json/clave_mac_logs.bin")
    contenido_para_mac = json.dumps(mac_obj, sort_keys=True, separators=(',',':'), ensure_ascii=False)
    hmac_valido = verificar_hmac_sha256(clave_mac, contenido_para_mac, ultima_entrada.get('mac', ''))

    # Verificar firma del usuario
    user_sig = ultima_entrada.get('user_sig')
    user_sig_result = 'No presente'
    if user_sig:
        usuarios_reg = cargar_usuarios('json/usuarios.json')
        pub_obj = None
        try:
            pub_pem = usuarios_reg.get(usuario_actual, {}).get('public_key_pem')
            if pub_pem:
                try:
                    pub_obj = serialization.load_pem_public_key(pub_pem.encode('utf-8'), backend=default_backend())
                except Exception:
                    pub_obj = None

            if pub_obj is None:
                pub_path = os.path.join('json', 'user_keys', f"{usuario_actual}_public.pem")
                if os.path.exists(pub_path):
                    try:
                        with open(pub_path, 'rb') as pf:
                            pub_bytes = pf.read()
                        pub_obj = serialization.load_pem_public_key(pub_bytes, backend=default_backend())
                    except Exception:
                        pub_obj = None

            if pub_obj is not None:
                try:
                    ok = verificar(pub_obj, contenido_para_firma, user_sig)
                    user_sig_result = 'Firma usuario válida' if ok else 'Firma usuario inválida'
                except Exception as e:
                    user_sig_result = f'Error verificando firma: {e}'
            else:
                user_sig_result = 'Clave pública de usuario no encontrada'
        except Exception as e:
            user_sig_result = f'Error verificando firma: {e}'

    # Verificar certificado del usuario 
    cert_result = 'No presente'
    try:
        usuarios_reg = cargar_usuarios('json/usuarios.json')
        ruta_cert = usuarios_reg.get(usuario_actual, {}).get('cert_path')

        cert_pem = None
        if ruta_cert and os.path.exists(ruta_cert):
            try:
                with open(ruta_cert, 'rb') as cf:
                    cert_pem = cf.read()
            except Exception:
                cert_pem = None

        if cert_pem is None:
            candidate = os.path.join('json', 'user_certs', f"{usuario_actual}.pem")
            if os.path.exists(candidate):
                try:
                    with open(candidate, 'rb') as cf:
                        cert_pem = cf.read()
                except Exception:
                    cert_pem = None

        if cert_pem:
            ok_cert, razon = verificar_cadena_certificado(cert_pem)
            cert_result = 'Certificado válido' if ok_cert else f'Certificado inválido: {razon}'
        else:
            cert_result = 'Certificado no encontrado'
    except Exception as e:
        cert_result = f'Error verificando certificado: {e}'

    # Mostrar resultados al usuario
    print('\n=== Resultado de verificación ===')
    print(f"vote_id: {mac_obj['vote_id']}")
    print(f"HMAC: {'válido' if hmac_valido else 'inválido'}")
    print(f"Firma usuario: {user_sig_result}")
    print(f"Certificado: {cert_result}")

    # Registrar la verificación en el log de verificaciones
    try:
        os.makedirs(os.path.dirname('json/logs/verification_log.jsonl'), exist_ok=True)
        ver_log = {
            'when': datetime.now().isoformat(),
            'user': usuario_actual,
            'vote_id': mac_obj['vote_id'],
            'hmac': 'válido' if hmac_valido else 'inválido',
            'user_sig': user_sig_result,
            'certificado': cert_result,
        }
        with open('json/logs/verification_log.jsonl', 'a', encoding='utf-8') as vf:
            vf.write(json.dumps(ver_log, ensure_ascii=False) + '\n')
    except Exception:
        pass

    try:
        input('\nPresione Enter para continuar...')
    except Exception:
        pass