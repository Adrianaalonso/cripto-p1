# Funciones MFA exactas del sistema_votacion.py original
import os
import json
import random
import time
import tkinter as tk
from funciones_cripto import _pbkdf2_hash, _verificar_password
from archivos_json import cargar_usuarios, guardar_usuarios
from datetime import datetime

def generar_codigo_mfa():
    """Generar código MFA de 6 dígitos"""
    return str(random.randint(100000, 999999))

def mostrar_codigo_ventana(codigo):
    """Mostrar código en una ventana simple"""
    # Crear ventana simple
    ventana = tk.Tk()
    ventana.title("Código de Verificación")
    ventana.geometry("250x100")
    ventana.resizable(False, False)
    texto = tk.Label(ventana, text=f"Tu código es: {codigo}", font=("Arial", 14))
    texto.pack(pady=20)
    boton = tk.Button(ventana, text="OK", command=ventana.destroy, width=10)
    boton.pack()
    ventana.mainloop()
    return True

def guardar_codigo_mfa(usuario, codigo):
    """Guardar código MFA temporalmente"""
    codigos = {}
    if os.path.exists("codigos_mfa.json"):
        with open("codigos_mfa.json", 'r') as f:
            codigos = json.load(f)
    
    codigos[usuario] = {
        "codigo": codigo,
        "timestamp": time.time()
    }
    
    with open("codigos_mfa.json", 'w') as f:
        json.dump(codigos, f, indent=2)

def verificar_codigo_mfa(usuario, codigo_ingresado):
    """Verificar código MFA"""
    if not os.path.exists("codigos_mfa.json"):
        return False, "No hay código pendiente"
        
    with open("codigos_mfa.json", 'r') as f:
        codigos = json.load(f)
    
    if usuario not in codigos:
        return False, "No hay código pendiente"
    
    codigo_info = codigos[usuario]
    
 
    if time.time() - codigo_info["timestamp"] > 150:
        del codigos[usuario]
        with open("codigos_mfa.json", 'w') as f:
            json.dump(codigos, f, indent=2)
        return False, "Código expirado"
    
    # Verificar código
    if codigo_info["codigo"] == codigo_ingresado:
        del codigos[usuario]
        with open("codigos_mfa.json", 'w') as f:
            json.dump(codigos, f, indent=2)
        return True, "Código correcto"
    
    return False, "Código incorrecto"

def registrar_usuario(archivo_usuarios):
    """Registrar un nuevo usuario"""
    print("\n--- REGISTRO DE USUARIO ---")
    
    usuarios = cargar_usuarios(archivo_usuarios)
    
    # Solicitar datos de registro
    usuario = input("Ingrese nombre de usuario: ").strip()
    if usuario in usuarios:
        print("El usuario ya existe. Intente con otro nombre.")
        return False
    
    import getpass
    email = input("Ingrese su email: ").strip()
    password = getpass.getpass("Ingrese su contraseña: ")
    password_confirm = getpass.getpass("Confirme su contraseña: ")
    
    if password != password_confirm:
        print("Las contraseñas no coinciden.")
        return False
    
    # Guardar usuario en usuarios.json
    usuarios[usuario] = {
        "email": email,
        "password": _pbkdf2_hash(password),
        "fecha_registro": datetime.now().isoformat()
    }
    
    guardar_usuarios(usuarios, archivo_usuarios)
    print(f"Usuario '{usuario}' registrado exitosamente!")
    return True

def iniciar_sesion(archivo_usuarios):
    """Iniciar sesión con usuario existente y MFA"""
    print("\n--- INICIAR SESIÓN ---")
    
    usuarios = cargar_usuarios(archivo_usuarios)
    
    import getpass
    usuario = input("Nombre de usuario: ").strip()
    password = getpass.getpass("Contraseña: ")
    
    if usuario in usuarios and  _verificar_password(password, usuarios[usuario]["password"]):
        # Primer factor válido, ahora MFA
        email_usuario = usuarios[usuario]["email"]
        
        # Generar y mostrar código
        codigo = generar_codigo_mfa()
        print(f"\n Mostrando código de verificación para {email_usuario}...")
        
        # Mostrar código en ventana
        if mostrar_codigo_ventana(codigo):
            # Guardar código temporalmente
            guardar_codigo_mfa(usuario, codigo)
            
            print(" Código mostrado.")
            
            # Solicitar código al usuario
            try:
                codigo_ingresado = input("Ingresa el código de 6 dígitos: ").strip()
                
                valido, mensaje = verificar_codigo_mfa(usuario, codigo_ingresado)
                
                if valido:
                    print(f"Bienvenido/a, {usuario}!")
                    return usuario
                else:
                    print(f"{mensaje}")
                    return None
                    
            except KeyboardInterrupt:
                print("\nVerificación cancelada.")
                return None
        else:
            print(" Error al mostrar código. Intenta más tarde.")
            return None
    else:
        print(" Usuario o contraseña incorrectos.")
        return None