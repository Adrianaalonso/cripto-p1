# Funciones de votación exactas del sistema_votacion.py original
from archivos_json import cargar_votos, guardar_votos

def votar(usuario_actual, opciones_votacion, archivo_votos):
    """Realizar votación"""
    votos = cargar_votos(archivo_votos)
    
    # Verificar si ya votó
    if usuario_actual in votos["usuarios_votaron"]:
        print("Ya has votado anteriormente. No puedes votar nuevamente.")
        return None
    
    print("\n--- OPCIONES DE VOTACIÓN ---")
    print("📦 1. Opción A")
    print("📦 2. Opción B")
    print("0. Cancelar")
    
    try:
        opcion = int(input("\nSeleccione su opción (1 o 2): "))
        if opcion not in (0, 1, 2):
            print("Opción no válida.")
            return None
        if opcion == 0:
            print("Votación cancelada.")
            return None
        # Registrar voto
        seleccion = opciones_votacion[opcion - 1]
        votos[seleccion] += 1
        votos["usuarios_votaron"].append(usuario_actual)
        guardar_votos(votos, archivo_votos)
        print(f"Voto registrado para: {seleccion}")
        return seleccion
            
    except ValueError:
        print("Por favor ingrese un número válido.")
        return None

def mostrar_resultados(archivo_votos):
    """Mostrar resultados de la votación"""
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
    input("\nPresiona Enter para continuar...")