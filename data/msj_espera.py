"""Mensajes de pausa para la aplicación."""

PAUSE_PROMPT = "\nPresiona Enter para continuar..."


def pause(prompt: str = PAUSE_PROMPT) -> None:
    """Pausa la ejecución hasta que el usuario presione Enter.

    Mantiene un único lugar donde cambiar el texto si se necesita
    internacionalización o ajustes.
    """
    try:
        input(prompt)
    except (KeyboardInterrupt, EOFError):
        # No hacemos nada especial al cancelar la pausa
        return
