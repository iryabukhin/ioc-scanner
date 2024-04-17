
import abc
from typing import Union, Optional

from scanner.config import ConfigObject
from scanner.models import IndicatorItem, IndicatorItemOperator


class BaseHandler:

    def __init__(self, config: ConfigObject) -> None:
        self.config = config

    @staticmethod
    @abc.abstractmethod
    def get_supported_terms() -> list[str]:
        return []


    @abc.abstractmethod
    def validate(self, items: list[IndicatorItem], operator: IndicatorItemOperator) -> bool:
        raise NotImplementedError
