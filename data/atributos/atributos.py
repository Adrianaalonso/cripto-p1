"""Clase base para validadores de atributos de cuenta."""
import re
from ..msj_error import ExceptionErrors

class Attribute:
    """Validador base para atributos (usa regex en fullmatch)."""

    def __init__(self):
        self._validation_pattern: str = r""
        self._error_message: str = ""
        self._attr_value: str = ""

    def validate(self, attr_value: str) -> str:
        """Valida attr_value; lanza ExceptionErrors en caso de fallo."""
        if attr_value is None:
            raise ExceptionErrors(self._error_message)
        pattern = re.compile(self._validation_pattern)
        if not pattern.fullmatch(attr_value):
            raise ExceptionErrors(self._error_message)
        return attr_value

    @property
    def value(self) -> str:
        """Retorna el valor validado (si ya se estableció)."""
        return self._attr_value

    @value.setter
    def value(self, attr_value: str):
        """Valida y asigna el valor del atributo."""
        self._attr_value = self.validate(attr_value)