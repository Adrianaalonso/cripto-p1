"""Validador de nombre de usuario: mínimo 3 caracteres; letras, dígitos y _ permitidos."""
from .atributos import Attribute
from ..msj_config import INVALID_USERNAME
from ..msj_error import ExceptionErrors
import json

class Username(Attribute):
    """Validador para nombre de usuario."""
    def __init__(self, attr_value: str):
        super().__init__()
        # 3 o más caracteres; solo letras, dígitos o underscore
        self._validation_pattern = r"^[A-Za-z0-9_]{3,}$"
        self._error_message = INVALID_USERNAME
        self._attr_value = self.validate(attr_value)