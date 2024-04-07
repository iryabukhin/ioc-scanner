
import abc
from typing import  List, Dict, Union, Optional

from scanner.config import ConfigObject
from scanner.models import IndicatorItem, IndicatorItemOperator


class BaseHandler:

    def __init__(self, config: ConfigObject) -> None:
        self.config = config

    @staticmethod
    @abc.abstractmethod
    def get_supported_terms() -> List[str]:
        return []


    @abc.abstractmethod
    def validate(self, items: List[IndicatorItem], operator: IndicatorItemOperator) -> bool:
        raise NotImplementedError
