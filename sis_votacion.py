# Archivo principal 
from mfa import registrar_usuario, iniciar_sesion, iniciar_sesion_admin
from sistema_votos import votar, mostrar_resultados, solicitar_verificacion
from admin import ejecutar_panel_admin
from data import msj_comunes as msj

class SistemaVotacion:
    def __init__(self):
        self.archivo_usuarios = "json/usuarios.json"
        self.archivo_votos = "json/votos/votos.json"
        self.usuario_actual = None
        self.opciones_votacion = ["Opción A", "Opción B"]
        self.archivo_log_cifrado = "json/votos/log_cifrado.jsonl"
        self.archivo_clave = "json/clave_aes.bin"
    
    def mostrar_menu_principal(self):
        """muestra el menu principal"""
        print("\n" + msj.LINEA_MENU)
        print(msj.TITULO_MENU)
        print(msj.LINEA_MENU)
        print(msj.OP_INICIAR)
        print(msj.OP_REGISTRARSE)
        print(msj.OP_SALIR)
        print(msj.LINEA_MENU)
    
    def mostrar_menu_votacion(self):
        """muestra menú de votación"""
        print("\n" + msj.LINEA_VOTACION)
        print(msj.bienvenida(self.usuario_actual))
        print(msj.LINEA_VOTACION)
        print(msj.TITULO_VOTACION)
        print(msj.LINEA_VOTACION)
        print(msj.OP_VOTAR)
        print(msj.OP_VER_RESULTADOS)
        print(msj.OP_VERIFICAR_VOTO)
        print(msj.OP_CERRAR_SESION)
        print(msj.LINEA_VOTACION)
    
    def ejecutar(self):
        """ejecuta sistema principal"""
        print(msj.INICIANDO)

        while True:
            if not self.usuario_actual:
                # Menú principal para iniciar sesión, registrarse o salir
                self.mostrar_menu_principal()
                
                try:
                    opcion = input(msj.PROMPT_SELECCIONAR)
                    
                    if opcion == "1":
                        resultado = iniciar_sesion(self.archivo_usuarios)
                        if resultado:
                            tipo_usuario, nombre_usuario = resultado
                            if tipo_usuario == "admin":
                                # Mostrar panel de administrador
                                ejecutar_panel_admin(nombre_usuario)
                            else:
                                # Establecer usuario actual
                                self.usuario_actual = nombre_usuario
                    elif opcion == "2":
                        registrar_usuario(self.archivo_usuarios)
                    elif opcion == "3":
                        print(msj.GRACIAS)
                        break
                    else:
                        print(msj.OPCION_INVALIDA)
                
                except KeyboardInterrupt:
                    print(msj.HASTA_LUEGO)
                    break
            else:
                # Menú de votación (autenticado)
                self.mostrar_menu_votacion()
                
                try:
                    opcion = input(msj.PROMPT_SELECCIONAR)
                    
                    if opcion == "1":
                        votar(self.usuario_actual, self.opciones_votacion, self.archivo_votos)
                        # El cifrado híbrido + HMAC ya se hace dentro de votar()
                    elif opcion == "2":
                        mostrar_resultados(self.archivo_votos)
                    elif opcion == "3":
                        solicitar_verificacion(self.usuario_actual)
                    elif opcion == "4":
                        print(msj.despedida(self.usuario_actual))
                        self.usuario_actual = None
                    else:
                        print(msj.OPCION_INVALIDA)
                
                except KeyboardInterrupt:
                    print(f"\n Hasta luego, {self.usuario_actual}!")
                    break

if __name__ == "__main__":
    SistemaVotacion().ejecutar()
    #sistema = SistemaVotacion()
    #sistema.ejecutar()