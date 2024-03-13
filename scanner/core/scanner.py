import itertools
import typing
from typing import List, Dict, Union, Optional
from  scanner.exceptions import UnsupportedOpenIocTerm

from scanner.core import BaseHandler
from scanner.models import (
    Indicator,
    IndicatorItem,
    IndicatorItemOperator,
    IndicatorItemCondition,
    IndicatorItemContent
)

class IOCScanner:
    def __init__(self):
        self.lazy_evaluation = False
        self.scanned_iocs = {}
        self.handlers: Dict[str, BaseHandler] = {}

    def __init_handlers(self):
        pass

    def process(self, indicators: List[Indicator]):
        result = False
        matched_indicators = []
        for indicator in indicators:
            valid_items = []
            for item in indicator.items:
                for handler in self.handlers:
                    if handler.can_process(item) and handler.validate(item):
                         valid_items.append(item)

    def validate_indicator(self, indicator: Indicator):
        valid_children = list()
        child_items: typing.List[IndicatorItem] = list()
        child_indicators = list()
        for child in indicator.items:
            if isinstance(child, IndicatorItem):
                child_items.append(child)
            elif isinstance(child, Indicator):
                child_indicators.append(child)

        for item_type, child_items in itertools.groupby(child_items, key=lambda i: i.context.document):
            if self.handlers.get(item_type, None) is None:
                raise UnsupportedOpenIocTerm('Unknown data type!')
            handler = self.handlers.get(item_type)
            result = handler.validate(child_items, indicator.operator)
            if result:
                valid_children.extend(child_items)

        for child_indicator in child_indicators:
            if self.validate_indicator(child_indicator):
                valid_children.append(indicator)

        result = True
        if indicator.operator is IndicatorItemOperator.OR:

