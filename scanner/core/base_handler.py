
import abc
from typing import Union, Optional

from scanner.config import ConfigObject
from scanner.models import IndicatorItem, IndicatorItemOperator, ValidationResult


class BaseHandler:

    def __init__(self, config: ConfigObject) -> None:
        self.config = config
        self._lazy_evaluation = config.get('lazy_evaluation', True)
        self._ignore_errors = config.get('ignore_errors', False)

    @staticmethod
    @abc.abstractmethod
    def get_supported_terms() -> list[str]:
        return []


    @abc.abstractmethod
    def validate(self, items: list[IndicatorItem], operator: IndicatorItemOperator) -> ValidationResult:
        raise NotImplementedError
