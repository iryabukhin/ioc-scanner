
import abc
from typing import  List, Dict, Union, Optional
from scanner.models import IndicatorItem, IndicatorItemOperator


class BaseHandler:
    @abc.abstractmethod
    def can_process(self, item: IndicatorItem) -> bool:
        raise NotImplementedError

    @abc.abstractmethod
    def validate(self, items: List[IndicatorItem], operator: IndicatorItemOperator) -> bool:
        raise NotImplementedError
