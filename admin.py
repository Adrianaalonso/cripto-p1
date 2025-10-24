# Menú y funciones específicas para administradores
from cifrado import exportar_log_descifrado
from sistema_votos import mostrar_resultados

def mostrar_menu_admin():
    """Mostrar menú de opciones para administradores"""
    print("\n" + "="*40)
    print("   PANEL DE ADMINISTRADOR")
    print("="*40)
    print("1. Exportar log de auditoría descifrado")
    print("2. Cerrar sesión")
    print("="*40)

def ejecutar_panel_admin(usuario_admin):
    """Ejecutar panel de administrador"""
    print(f"\n Acceso de administrador: {usuario_admin}")
    
    while True:
        mostrar_menu_admin()
        
        try:
            opcion = input("\nSeleccione una opción: ")
            
            if opcion == "1":
                print("\n=== EXPORTANDO LOG DE AUDITORÍA ===")
                # Sin pedir contraseña para administradores
                exportar_log_descifrado("log_cifrado.jsonl", "clave_aes.bin", admin_mode=True)
                
            elif opcion == "2":
                print(f" Cerrando sesión de administrador: {usuario_admin}")
                break
                
            else:
                print(" Opción no válida. Intente nuevamente.")
                
        except KeyboardInterrupt:
            print(f"\n Cerrando sesión de administrador: {usuario_admin}")
            break
    
    return None