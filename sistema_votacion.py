import os
import json
import hashlib
import getpass
from datetime import datetime

class SistemaVotacion:
    def __init__(self):
        self.archivo_usuarios = "usuarios.json"
        self.archivo_votos = "votos.json"
        self.usuario_actual = None
        self.opciones_votacion = ["Opción A", "Opción B", "Opción C"]
        
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
    
    def cargar_votos(self):
        """Cargar votos desde el archivo JSON"""
        if os.path.exists(self.archivo_votos):
            with open(self.archivo_votos, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {"Opción A": 0, "Opción B": 0, "usuarios_votaron": []}
    
    def guardar_votos(self, votos):
        """Guardar votos en el archivo JSON"""
        with open(self.archivo_votos, 'w', encoding='utf-8') as f:
            json.dump(votos, f, indent=2, ensure_ascii=False)
    
    def hash_password(self, password):
        """Encriptar contraseña usando SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def mostrar_menu_principal(self):
        """Mostrar el menú principal"""
        print("\n" + "="*50)
        print("   SISTEMA DE VOTACIÓN INTELIGENTE")
        print("="*50)
        print("1. Iniciar Sesión")
        print("2. Registrarse")
        print("3. Salir")
        print("="*50)
    
    def registrar_usuario(self):
        """Registrar un nuevo usuario"""
        print("\n--- REGISTRO DE USUARIO ---")
        
        usuarios = self.cargar_usuarios()
        
        # Solicitar datos
        usuario = input("Ingrese nombre de usuario: ").strip()
        if usuario in usuarios:
            print("❌ El usuario ya existe. Intente con otro nombre.")
            return False
        
        email = input("Ingrese su email: ").strip()
        password = getpass.getpass("Ingrese su contraseña: ")
        password_confirm = getpass.getpass("Confirme su contraseña: ")
        
        if password != password_confirm:
            print("❌ Las contraseñas no coinciden.")
            return False
        
        # Guardar usuario
        usuarios[usuario] = {
            "email": email,
            "password": self.hash_password(password),
            "fecha_registro": datetime.now().isoformat()
        }
        
        self.guardar_usuarios(usuarios)
        print(f"✅ Usuario '{usuario}' registrado exitosamente!")
        return True
    
    def iniciar_sesion(self):
        """Iniciar sesión con usuario existente"""
        print("\n--- INICIAR SESIÓN ---")
        
        usuarios = self.cargar_usuarios()
        
        usuario = input("Nombre de usuario: ").strip()
        password = getpass.getpass("Contraseña: ")
        
        if usuario in usuarios and usuarios[usuario]["password"] == self.hash_password(password):
            self.usuario_actual = usuario
            print(f"✅ Bienvenido/a, {usuario}!")
            return True
        else:
            print("❌ Usuario o contraseña incorrectos.")
            return False
    
    def mostrar_menu_votacion(self):
        """Mostrar el menú de votación"""
        print("\n" + "="*40)
        print(f"   BIENVENIDO/A: {self.usuario_actual}")
        print("="*40)
        print("🗳️  SISTEMA DE VOTACIÓN")
        print("="*40)
        print("1. Votar")
        print("2. Ver resultados")
        print("3. Cerrar sesión")
        print("="*40)
    
    def votar(self):
        """Realizar votación"""
        votos = self.cargar_votos()
        
        # Verificar si ya votó
        if self.usuario_actual in votos["usuarios_votaron"]:
            print("❌ Ya has votado anteriormente. No puedes votar nuevamente.")
            return
        
        print("\n--- OPCIONES DE VOTACIÓN ---")
        print("📦 1. Opción A")
        print("📦 2. Opción B")
        print("0. Cancelar")
        
        try:
            opcion = int(input("\nSeleccione su opción (1 o 2): "))
            
            if opcion == 1:
                votos["Opción A"] += 1
                votos["usuarios_votaron"].append(self.usuario_actual)
                self.guardar_votos(votos)
                print("✅ Voto registrado para: Opción A")
            elif opcion == 2:
                votos["Opción B"] += 1
                votos["usuarios_votaron"].append(self.usuario_actual)
                self.guardar_votos(votos)
                print("✅ Voto registrado para: Opción B")
            elif opcion == 0:
                print("Votación cancelada.")
            else:
                print("❌ Opción no válida.")
        except ValueError:
            print("❌ Por favor ingrese un número válido.")
    
    def mostrar_resultados(self):
        """Mostrar resultados de la votación"""
        votos = self.cargar_votos()
        
        total_votos = votos["Opción A"] + votos["Opción B"]
        
        print("\n" + "="*40)
        print("   📊 RESULTADOS DE VOTACIÓN")
        print("="*40)
        
        if total_votos > 0:
            print(f"📦 Opción A: {votos['Opción A']} votos ({votos['Opción A']/total_votos*100:.1f}%)")
            print(f"📦 Opción B: {votos['Opción B']} votos ({votos['Opción B']/total_votos*100:.1f}%)")
            print(f"\n📈 Total de votos: {total_votos}")
        else:
            print("📭 No hay votos registrados aún.")
        
        print("="*40)
    
    def ejecutar(self):
        """Ejecutar el sistema principal"""
        print("🚀 Iniciando Sistema de Votación...")
        
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
                        print("👋 ¡Gracias por usar el Sistema de Votación!")
                        break
                    else:
                        print("❌ Opción no válida. Intente nuevamente.")
                
                except KeyboardInterrupt:
                    print("\n👋 ¡Hasta luego!")
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
                        print(f"👋 Hasta luego, {self.usuario_actual}!")
                        self.usuario_actual = None
                    else:
                        print("❌ Opción no válida. Intente nuevamente.")
                
                except KeyboardInterrupt:
                    print(f"\n👋 Hasta luego, {self.usuario_actual}!")
                    break

if __name__ == "__main__":
    sistema = SistemaVotacion()
    sistema.ejecutar()
