"""Mensajes de pausa para la aplicación."""

PAUSE_PROMPT = "\nPresiona Enter para continuar..."


def pause(prompt: str = PAUSE_PROMPT) -> None:
    """Pausa la ejecución hasta que el usuario presione Enter."""
    try:
        input(prompt)
    except (KeyboardInterrupt, EOFError):
        return
