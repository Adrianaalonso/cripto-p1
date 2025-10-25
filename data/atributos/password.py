"""Validador de contraseña: mínimo 8 caracteres y al menos un carácter especial."""
from .atributos import Attribute
from ..msj_config import INVALID_PASSWORD

class Password(Attribute):
    """Validador para contraseñas básicas (min 8 y al menos un carácter especial)."""
    def __init__(self, attr_value: str):
        super().__init__()
        # Al menos 8 caracteres y al menos un carácter no alfanumérico
        self._validation_pattern = r"^(?=.{8,}$)(?=.*[^A-Za-z0-9]).+$"
        self._error_message = INVALID_PASSWORD
        self._attr_value = self.validate(attr_value)