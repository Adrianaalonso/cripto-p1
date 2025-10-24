# Archivo principal - EXACTAMENTE como sistema_votacion.py original pero refactorizado
from mfa import registrar_usuario, iniciar_sesion, iniciar_sesion_admin
from sistema_votos import votar, mostrar_resultados  
from cifrado import registrar_log_hibrido_hmac, exportar_log_descifrado
from admin import ejecutar_panel_admin

class SistemaVotacion:
    def __init__(self):
        self.archivo_usuarios = "usuarios.json"
        self.archivo_votos = "votos.json"
        self.usuario_actual = None
        self.opciones_votacion = ["Opción A", "Opción B"]
        self.archivo_log_cifrado = "log_cifrado.jsonl"
        self.archivo_clave = "clave_aes.bin"
    
    def mostrar_menu_principal(self):
        """Mostrar el menú principal"""
        print("\n" + "="*50)
        print("      *SISTEMA DE VOTACIÓN INTELIGENTE*")
        print("="*50)
        print("1. Iniciar Sesión")
        print("2. Registrarse")
        print("3. Salir")
        print("="*50)
    
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
                        resultado = iniciar_sesion(self.archivo_usuarios)
                        if resultado:
                            tipo_usuario, nombre_usuario = resultado
                            if tipo_usuario == "admin":
                                # Ejecutar panel de administrador
                                ejecutar_panel_admin(nombre_usuario)
                            else:
                                # Usuario normal
                                self.usuario_actual = nombre_usuario
                    elif opcion == "2":
                        registrar_usuario(self.archivo_usuarios)
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
                        seleccion = votar(self.usuario_actual, self.opciones_votacion, self.archivo_votos)
                        # El cifrado híbrido + HMAC ya se hace dentro de votar()
                    elif opcion == "2":
                        mostrar_resultados(self.archivo_votos)
                    elif opcion == "3":
                        print(f" Hasta luego, {self.usuario_actual}!")
                        self.usuario_actual = None
                    else:
                        print(" Opción no válida. Intente nuevamente.")
                
                except KeyboardInterrupt:
                    print(f"\n Hasta luego, {self.usuario_actual}!")
                    break

if __name__ == "__main__":
    sistema = SistemaVotacion()
    sistema.ejecutar()