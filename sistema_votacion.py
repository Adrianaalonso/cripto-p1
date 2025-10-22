import os
import json
import hashlib
import getpass
import random
import time
import hmac
import base64
import tkinter as tk
from tkinter import messagebox
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


PBKDF2_ITERS = 200_000

class SistemaVotacion:
    def __init__(self):
        self.archivo_usuarios = "usuarios.json"
        self.archivo_votos = "votos.json"
        self.usuario_actual = None
        self.opciones_votacion = ["Opción A", "Opción B"]
        self.archivo_log_cifrado = "log_cifrado.jsonl"
        self.archivo_clave = "clave_aes.bin"

        
    def cargar_usuarios(self):
        """Cargar usuarios desde el archivo JSON"""
        if os.path.exists(self.archivo_usuarios):
            with open(self.archivo_usuarios, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {}
    
    def guardar_usuarios(self, usuarios):
        """Guardar usuarios en el archivo JSON"""
        with open(self.archivo_usuarios, 'w', encoding='utf-8') as f:
            json.dump(usuarios, f, indent=2, ensure_ascii=False)
    
    def generar_clave_aes(self):
        """Generar clave AES de 256 bits"""
        return os.urandom(32)  # 32 bytes = 256 bits
    
    def cifrar_mensaje(self, clave, mensaje: str):
        """Cifrar mensaje con AES-GCM"""
        iv = os.urandom(12)  # nonce recomendado para GCM
        aes = Cipher(algorithms.AES(clave), modes.GCM(iv), backend=default_backend()).encryptor()
        cifrado = aes.update(mensaje.encode()) + aes.finalize()
        # empaquetamos IV + tag + texto cifrado
        paquete = iv + aes.tag + cifrado
        resultado = base64.b64encode(paquete).decode()
        print(f"[LOG] Cifrado realizado con AES-GCM (clave 256 bits)")
        print(f"[LOG] Texto original: {mensaje}")
        print(f"[LOG] Texto cifrado (base64): {resultado}\n")
        return resultado
    
    def descifrar_mensaje(self, clave, cifrado_b64: str):
        """Descifrar mensaje con AES-GCM"""
        paquete = base64.b64decode(cifrado_b64)
        iv, tag, cifrado = paquete[:12], paquete[12:28], paquete[28:]
        aes = Cipher(algorithms.AES(clave), modes.GCM(iv, tag), backend=default_backend()).decryptor()
        texto = aes.update(cifrado) + aes.finalize()
        print(f"[LOG] Descifrado realizado con AES-GCM (clave 256 bits)")
        print(f"[LOG] Texto descifrado: {texto.decode()}\n")
        return texto.decode()

    def cargar_votos(self):
        """Cargar votos desde el archivo JSON"""
        defaults = {"Opción A": 0, "Opción B": 0, "usuarios_votaron": []}
        if os.path.exists(self.archivo_votos):
            try:
                with open(self.archivo_votos, 'r', encoding='utf-8') as f:
                    v = json.load(f)
            except Exception:
                # fichero corrupto → empezamos limpio
                return defaults.copy()
            # Rellenar claves faltantes
            for k, val in defaults.items():
                v.setdefault(k, val if not isinstance(val, list) else list(val))
            return v
        return defaults.copy()
        
    def guardar_votos(self, votos):
        """Guardar votos en el archivo JSON"""
        with open(self.archivo_votos, 'w', encoding='utf-8') as f:
            json.dump(votos, f, indent=2, ensure_ascii=False)
    
    def _pbkdf2_hash(self, password:str, salt: bytes=None, iters = PBKDF2_ITERS):
        if salt is None:
            salt = os.urandom(16)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iters)
        return f"pbkdf2$sha256${iters}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"
    
    def _verificar_password(self, password: str, stored: str) -> bool:
        try:
            scheme, algo, iters, salt_b64, dk_b64 = stored.split('$', 4)
            assert scheme == 'pbkdf2' and algo == 'sha256'
            salt = base64.b64decode(salt_b64)
            dk_stored = base64.b64decode(dk_b64)
            dk_new = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, int(iters))
            return hmac.compare_digest(dk_new, dk_stored)
        except Exception:
            return False

    def generar_codigo_mfa(self):
        """Generar código MFA de 6 dígitos"""
        return str(random.randint(100000, 999999))
    
    def mostrar_codigo_ventana(self, codigo):
        """Mostrar código en una ventana simple"""
        # Crear ventana simple
        ventana = tk.Tk()
        ventana.title("Código de Verificación")
        ventana.geometry("250x100")
        ventana.resizable(False, False)
        
        # Texto simple
        texto = tk.Label(ventana, text=f"Tu código es: {codigo}", font=("Arial", 14))
        texto.pack(pady=20)
        
        # Botón OK
        boton = tk.Button(ventana, text="OK", command=ventana.destroy, width=10)
        boton.pack()
        
        # Mostrar ventana
        ventana.mainloop()
        return True
    
    def guardar_codigo_mfa(self, usuario, codigo):
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
    
    def verificar_codigo_mfa(self, usuario, codigo_ingresado):
        """Verificar código MFA"""
        if not os.path.exists("codigos_mfa.json"):
            return False, "No hay código pendiente"
            
        with open("codigos_mfa.json", 'r') as f:
            codigos = json.load(f)
        
        if usuario not in codigos:
            return False, "No hay código pendiente"
        
        codigo_info = codigos[usuario]
        
        # Verificar expiración (5 minutos = 300 segundos)
        if time.time() - codigo_info["timestamp"] > 300:
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
    
    def _cargar_o_crear_clave_maestra(self):
        """Clave AES-256 persistente para el log cifrado."""
        if os.path.exists(self.archivo_clave):
            with open(self.archivo_clave, "rb") as f:
                key = f.read()
            if len(key) == 32:
                return key
        key = os.urandom(32)  # 256 bits
        with open(self.archivo_clave, "wb") as f:
            f.write(key)
        try:
            os.chmod(self.archivo_clave, 0o600)  # Unix; en Windows ignora
        except Exception:
            pass
        return key
    
    def cifrar_para_log(self, clave, mensaje: str):
        iv = os.urandom(12)
        aes = Cipher(algorithms.AES(clave), modes.GCM(iv), backend=default_backend()).encryptor()
        ct = aes.update(mensaje.encode()) + aes.finalize()
        return {
            "algoritmo": "AES-GCM",
            "key_bits": 256,
            "iv_b64": base64.b64encode(iv).decode(),
            "tag_b64": base64.b64encode(aes.tag).decode(),
            "ct_b64": base64.b64encode(ct).decode(),
        }

    def descifrar_de_log(self, clave, iv_b64, tag_b64, ct_b64) -> str:
        iv = base64.b64decode(iv_b64)
        tag = base64.b64decode(tag_b64)
        ct  = base64.b64decode(ct_b64)
        aes = Cipher(algorithms.AES(clave), modes.GCM(iv, tag), backend=default_backend()).decryptor()
        return (aes.update(ct) + aes.finalize()).decode()

    def registrar_log_cifrado(self, usuario: str, seleccion: str):
        clave = self._cargar_o_crear_clave_maestra()
        mensaje = f"Voto de {usuario} para {seleccion} @ {datetime.now().isoformat(timespec='seconds')}"
        blob = self.cifrar_para_log(clave, mensaje)
        linea = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "usuario": usuario,          # si prefieres más privacidad, elimina o pseudonimiza este campo
            "opcion": seleccion,         # idem (se puede omitir para máxima privacidad)
            **blob
        }
        with open(self.archivo_log_cifrado, "a", encoding="utf-8") as f:
            f.write(json.dumps(linea, ensure_ascii=False) + "\n")

    def exportar_log_descifrado(self, salida="log_descifrado.jsonl"):
        if not os.path.exists(self.archivo_log_cifrado):
            print("No hay log cifrado que exportar.")
            return
        clave = self._cargar_o_crear_clave_maestra()
        out = []
        with open(self.archivo_log_cifrado, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                rec = json.loads(line)
                try:
                    texto = self.descifrar_de_log(clave, rec["iv_b64"], rec["tag_b64"], rec["ct_b64"])
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


    
    def mostrar_menu_principal(self):
        """Mostrar el menú principal"""
        print("\n" + "="*50)
        print("      *SISTEMA DE VOTACIÓN INTELIGENTE*")
        print("="*50)
        print("1. Iniciar Sesión")
        print("2. Registrarse")
        print("3. Salir")
        print("="*50)
    
    def registrar_usuario(self):
        """Registrar un nuevo usuario"""
        print("\n--- REGISTRO DE USUARIO ---")
        
        usuarios = self.cargar_usuarios()
        
        # Solicitar datos de registro
        usuario = input("Ingrese nombre de usuario: ").strip()
        if usuario in usuarios:
            print("El usuario ya existe. Intente con otro nombre.")
            return False
        
        email = input("Ingrese su email: ").strip()
        password = getpass.getpass("Ingrese su contraseña: ")
        password_confirm = getpass.getpass("Confirme su contraseña: ")
        
        if password != password_confirm:
            print("Las contraseñas no coinciden.")
            return False
        
        # Guardar usuario en usuarios.json
        usuarios[usuario] = {
            "email": email,
            "password": self._pbkdf2_hash(password),
            "fecha_registro": datetime.now().isoformat()
        }
        
        self.guardar_usuarios(usuarios)
        print(f"Usuario '{usuario}' registrado exitosamente!")
        return True
    def iniciar_sesion(self):
        """Iniciar sesión con usuario existente y MFA"""
        print("\n--- INICIAR SESIÓN ---")
        
        usuarios = self.cargar_usuarios()
        
        usuario = input("Nombre de usuario: ").strip()
        password = getpass.getpass("Contraseña: ")
        
        if usuario in usuarios and  self._verificar_password(password, usuarios[usuario]["password"]):
            # Primer factor válido, ahora MFA
            email_usuario = usuarios[usuario]["email"]
            
            # Generar y mostrar código
            codigo = self.generar_codigo_mfa()
            print(f"\n Mostrando código de verificación para {email_usuario}...")
            
            # Mostrar código en ventana
            if self.mostrar_codigo_ventana(codigo):
                # Guardar código temporalmente
                self.guardar_codigo_mfa(usuario, codigo)
                
                print(" Código mostrado.")
                
                # Solicitar código al usuario
                try:
                    codigo_ingresado = input("Ingresa el código de 6 dígitos: ").strip()
                    
                    valido, mensaje = self.verificar_codigo_mfa(usuario, codigo_ingresado)
                    
                    if valido:
                        self.usuario_actual = usuario
                        print(f"Bienvenido/a, {usuario}!")
                        return True
                    else:
                        print(f"{mensaje}")
                        return False
                        
                except KeyboardInterrupt:
                    print("\nVerificación cancelada.")
                    return False
            else:
                print(" Error al mostrar código. Intenta más tarde.")
                return False
        else:
            print(" Usuario o contraseña incorrectos.")
            return False
    
    def mostrar_menu_votacion(self):
        """Mostrar el menú de votación"""
        print("\n" + "="*40)
        print(f"   BIENVENIDO/A: {self.usuario_actual}")
        print("="*40)
        print("   SISTEMA DE VOTACIÓN")
        print("="*40)
        print("1. Votar")
        print("2. Ver resultados")
        print("3. Cerrar sesión")
        print("4. Exportar log descifrado (auditoría)")
        print("="*40)
    
    def votar(self):
        """Realizar votación"""
        votos = self.cargar_votos()
        
        # Verificar si ya votó
        if self.usuario_actual in votos["usuarios_votaron"]:
            print("Ya has votado anteriormente. No puedes votar nuevamente.")
            return
        
        print("\n--- OPCIONES DE VOTACIÓN ---")
        print("📦 1. Opción A")
        print("📦 2. Opción B")
        print("0. Cancelar")
        
        try:
            opcion = int(input("\nSeleccione su opción (1 o 2): "))
            if opcion not in (0, 1, 2):
                print("Opción no válida.")
                return
            if opcion == 0:
                print("Votación cancelada.")
                return
            # Registrar voto
            seleccion = self.opciones_votacion[opcion - 1]
            votos[seleccion] += 1
            votos["usuarios_votaron"].append(self.usuario_actual)
            self.guardar_votos(votos)
            print(f"Voto registrado para: {seleccion}")

            # ===== Punto 2: demostración de cifrado/descifrado visible =====
            self.registrar_log_cifrado(self.usuario_actual, seleccion)
                
        except ValueError:
            print("Por favor ingrese un número válido.")
    
    def mostrar_resultados(self):
        """Mostrar resultados de la votación"""
        votos = self.cargar_votos()
        
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
    
    def ejecutar(self):
        """Ejecutar el sistema principal"""
        print("Iniciando Sistema de Votación...")
        
        while True:
            if not self.usuario_actual:
                # Menú principal (no autenticado)
                self.mostrar_menu_principal()
                
                try:
                    opcion = input("\nSeleccione una opción: ")
                    
                    if opcion == "1":
                        self.iniciar_sesion()
                    elif opcion == "2":
                        self.registrar_usuario()
                    elif opcion == "3":
                        print("¡Gracias por usar el Sistema de Votación!")
                        break
                    else:
                        print("Opción no válida. Intente nuevamente.")
                
                except KeyboardInterrupt:
                    print("\n ¡Hasta luego!")
                    break
            else:
                # Menú de votación (autenticado)
                self.mostrar_menu_votacion()
                
                try:
                    opcion = input("\nSeleccione una opción: ")
                    
                    if opcion == "1":
                        self.votar()
                    elif opcion == "2":
                        self.mostrar_resultados()
                    elif opcion == "3":
                        print(f" Hasta luego, {self.usuario_actual}!")
                        self.usuario_actual = None
                    elif opcion == "4":
                        self.exportar_log_descifrado()

                    else:
                        print(" Opción no válida. Intente nuevamente.")
                
                except KeyboardInterrupt:
                    print(f"\n Hasta luego, {self.usuario_actual}!")
                    break

if __name__ == "__main__":
    sistema = SistemaVotacion()
    sistema.ejecutar()
