# Funciones MFA exactas del sistema_votacion.py original
import os
import json
import random
import time
import tkinter as tk
from crypto import _pbkdf2_hash, _verificar_password
from crypto.mac_usuario import generar_mac_usuario, verificar_mac_usuario
from archivos_json import cargar_usuarios, guardar_usuarios
from datetime import datetime

# Importar validadores y excepción
from data.atributos import Username, Password, Email
from data.msj_error import ExceptionErrors 
from data import msj_comunes as msj


def generar_codigo_mfa():
    """Generar código MFA de 6 dígitos"""
    return str(random.randint(100000, 999999))

def mostrar_codigo_ventana(codigo):
    """Mostrar código en una ventana simple"""
    # Crear ventana simple con el código de verificacion
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
    """Registrar un nuevo usuario con validaciones y mensajes claros."""
    print("\n--- REGISTRO DE USUARIO ---")
    usuarios = cargar_usuarios(archivo_usuarios)

    # === Username ===
    while True:
        usuario_raw = input(msj.PROMPT_USUARIO).strip()
        try:
            usuario = Username(usuario_raw).value  # valida: regex y longitud
        except ExceptionErrors as e:
            print(e.message)  
            continue

        if usuario in usuarios:
            print("El usuario ya existe. Intente con otro nombre.")
            continue
        break

    # === Email ===
    while True:
        email_raw = input(msj.PROMPT_CORREO).strip()
        try:
            email = Email(email_raw).value  # valida según tu política (p.ej. @gmail.com)
            break
        except ExceptionErrors as e:
            print(e.message) 

    # === contraseña ===
    import getpass
    while True:
        pwd1 = getpass.getpass("Ingrese su contraseña: ")
        try:
            pwd = Password(pwd1).value 
        except ExceptionErrors as e:
            print(e.message)
            continue

        pwd2 = getpass.getpass("Confirme su contraseña: ")
        if pwd1 != pwd2:
            print("Las contraseñas no coinciden.")
            continue
        password_ok = pwd1
        break

    # Guardar usuario
    usuarios[usuario] = {
        "email": email,
        "password": _pbkdf2_hash(password_ok),
        "fecha_registro": datetime.now().isoformat()
    }
    # Generar y añadir MAC por usuario para detección de manipulaciones
    try:
        usuarios[usuario]["mac"] = generar_mac_usuario(usuarios[usuario])
    except Exception:
        # Si hay un problema generando la MAC, todavía guardamos el usuario
        # pero dejamos el registro sin campo 'mac'. La verificación en login
        # bloqueará a usuarios sin 'mac' hasta que se migren.
        pass

    guardar_usuarios(usuarios, archivo_usuarios)
    print(f"Usuario '{usuario}' registrado exitosamente!")
    return True

def iniciar_sesion(archivo_usuarios):
    """Iniciar sesión con usuario existente y MFA"""
    print("\n--- INICIAR SESIÓN ---")
    
    usuarios = cargar_usuarios(archivo_usuarios)
    administradores = cargar_administradores()
    
    import getpass
    usuario = input(msj.PROMPT_LOGIN_USERNAME).strip()
    password = getpass.getpass("Contraseña: ")
    
    # Verificar si es administrador
    if usuario in administradores and _verificar_password(password, administradores[usuario]["password"]):
        nombre = administradores[usuario]["nombre"]
        print(f" ¡Bienvenido, {nombre}!")
        return ("admin", usuario)  # Retorna tupla indicando que es admin
    
    # Verificar usuario normal
    elif usuario in usuarios:
        user_record = usuarios[usuario]

        # Si el registro incluye MAC, verificar integridad del registro
        if "mac" in user_record:
            try:
                if not verificar_mac_usuario(user_record):
                    print("Registro de usuario modificado o corrupto: integridad comprometida. No se permite iniciar sesión.")
                    return None
            except Exception as e:
                print(f"Error verificando integridad del registro de usuario: {e}")
                return None
        else:
            # No existe MAC para este usuario: por seguridad, no permitimos login hasta migración
            print("Registro de usuario sin protección MAC: por seguridad, el inicio de sesión está bloqueado para este usuario.")
            print("Ejecute la migración para añadir MACs a los registros de usuario o regístrese de nuevo.")
            return None

        # Si la integridad es correcta, verificar contraseña
        if _verificar_password(password, user_record["password"]):
            # Primer factor válido, ahora MFA
            email_usuario = user_record["email"]

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
                    codigo_ingresado = input(msj.PROMPT_CODIGO).strip()

                    valido, mensaje = verificar_codigo_mfa(usuario, codigo_ingresado)

                    if valido:
                        print(f"Bienvenido/a, {usuario}!")
                        return ("user", usuario)  # Retorna tupla indicando que es usuario normal
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

def cargar_administradores():
    """Cargar lista de administradores del archivo"""
    try:
        with open("administradores.json", "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        return {}

def iniciar_sesion_admin():
    """Iniciar sesión como administrador"""
    administradores = cargar_administradores()
    
    if not administradores:
        print(" No hay administradores configurados.")
        return None 
    print("\n=== LOGIN ADMINISTRADOR ===")
    usuario = input(msj.PROMPT_USUARIO_ADMIN).strip()
    
    if usuario in administradores:
        import getpass
        password = getpass.getpass(" Contraseña: ")
        
        # Verificar contraseña del administrador
        if _verificar_password(password, administradores[usuario]["password"]):
            nombre = administradores[usuario]["nombre"]
            print(f" ¡Bienvenido, {nombre}!")
            return usuario
        else:
            print(" Credenciales de administrador incorrectas.")
            return None
    else:
        print(" Usuario administrador no encontrado.")
        return None