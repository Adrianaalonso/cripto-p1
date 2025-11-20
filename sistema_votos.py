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
)
from cifrado import registrar_log_hibrido_hmac
from data import msj_comunes as msj
from data import msj_espera
from crypto.signature_rsa import generar_par_claves_rsa, guardar_clave_privada, guardar_clave_publica
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64

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
        
        # Antes de registrar, ofrecer generar clave privada para firmar el voto si no existe
        os.makedirs("json/user_keys", exist_ok=True)
        user_priv_path = f"json/user_keys/{usuario_actual}_private.pem"
        if not os.path.exists(user_priv_path):
            try:
                generar = input("¿Desea generar ahora un par RSA para firmar sus votos? (s/n): ").strip().lower()
            except Exception:
                generar = 'n'
            if generar == 's':
                try:
                    priv_pem, pub_pem = generar_par_claves_rsa(bits=2048)
                    # guardar privada
                    try:
                        private_key_obj = serialization.load_pem_private_key(priv_pem, password=None, backend=default_backend())
                        guardar_clave_privada(user_priv_path, private_key_obj, passphrase=None)
                    except Exception:
                        with open(user_priv_path, 'wb') as f:
                            f.write(priv_pem)
                    # guardar pública en file y en usuarios.json
                    pub_path = f"json/user_keys/{usuario_actual}_public.pem"
                    try:
                        guardar_clave_publica(pub_path, pub_pem)
                    except Exception:
                        with open(pub_path, 'wb') as f:
                            f.write(pub_pem)
                    try:
                        usuarios_reg = cargar_usuarios('json/usuarios.json')
                        usuarios_reg[usuario_actual]['public_key_pem'] = pub_pem.decode('utf-8')
                        guardar_usuarios(usuarios_reg, 'json/usuarios.json')
                    except Exception:
                        pass
                    print(f"Par RSA generado. Claves guardadas en json/user_keys/ para {usuario_actual}.")
                except Exception as e:
                    print(f"Error generando claves RSA: {e}")

        # Registrar voto usando el helper unificado (cifrado híbrido + HMAC + firma)
        archivo_votos_cifrados = "json/votos_cifrados.jsonl"
        registrar_log_hibrido_hmac(usuario_actual, seleccion, archivo_votos_cifrados)

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