# Paquete data: exportaciones mínimas
from . import msj_error, msj_config, atributos

# msj_espera.py contiene la función pause() (antes llamada msj_ui).
# Exponemosla como `msj_ui` para mantener compatibilidad con el código
# que ya usa `from data import msj_ui`.
from . import msj_espera as msj_ui

__all__ = ["msj_error", "msj_config", "atributos", "msj_ui"]