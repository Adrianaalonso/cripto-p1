"""Validador de email: debe finalizar en @gmail.com"""
from .atributos import Attribute
from ..msj_config import INVALID_EMAIL

class Email(Attribute):
    """Validador para correos que deben terminar en @gmail.com"""
    def __init__(self, attr_value: str):
        super().__init__()
        # Local-part básico (no espacios, no @) y dominio gmail.com
        self._validation_pattern = r"^[^@\s]+@gmail\.com$"
        self._error_message = INVALID_EMAIL
        self._attr_value = self.validate(attr_value)