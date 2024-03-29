import importlib
import itertools
import os
from typing import List, Dict, Union, Optional

from loguru import logger
from scanner.exceptions import UnsupportedOpenIocTerm

from scanner.core import BaseHandler
from scanner.models import (
    Indicator,
    IndicatorItem,
    IndicatorItemOperator as Operator,
    IndicatorItemCondition,
    IndicatorItemContent
)

class IOCScanner:
    lazy_evaluation = False
    scanned_iocs = {}
    handlers: Dict[str, BaseHandler] = {}

    def __init__(self):
        self.__init_handlers()

    def __init_handlers(self):
        handlers_dir = os.getenv(
            'HANDLERS_BASE_DIR',
            os.path.join(os.path.dirname(os.path.dirname(__file__)), 'handlers')
        )
        for fname in os.listdir(handlers_dir):
            if fname.endswith('.py') and not fname == '__init__.py':
                try:
                    mn = fname[0:-3]
                    module = importlib.import_module(f'scanner.handlers.{mn}')
                    handler_instance, terms = module.init()
                    for term in terms:
                        self.handlers[term] = handler_instance
                except ImportError as e:
                    logger.error(f'Unable to import module {fname}: {e}')
                except Exception as e:
                    logger.error(f'Error loading handler from module {fname}: {e}')

    def process(self, indicators: List[Indicator]):
        return [i.id for i in indicators if self.validate_indicator(i)]

    def validate_indicator(self, indicator: Indicator) -> bool:
        if not self.handlers:
            raise Exception('No handlers have been loaded!')

        valid_children = (
            self._validate_indicator_items(indicator)
            + self._validate_child_indicators(indicator)
        )

        return self._evaluate_logic(valid_children, indicator)

    def _validate_indicator_items(self, indicator: Indicator) -> List[IndicatorItem]:
        """Validate indicator items within an indicator."""
        valid_items = []
        child_items = [i for i in indicator.items if isinstance(i, IndicatorItem)]

        # TODO: Move to __init_handlers method and make it into a property
        handlers_by_type = {}
        for k, v in self.handlers.items():
            type = k.split('/')[0]
            if type not in handlers_by_type:
                handlers_by_type[type] = v

        for item_type, items in itertools.groupby(child_items, key=lambda i: i.context.document):
            handler = handlers_by_type.get(item_type)
            if not handler:
                raise UnsupportedOpenIocTerm(f'Unknown data type: {item_type}')
            if handler.validate(items, indicator.operator):
                valid_items.extend(items)
        return valid_items

    def _validate_child_indicators(self, indicator: Indicator) -> List[Indicator]:
        """Recursively validate child indicators."""
        return [
            child for child in indicator.items
            if isinstance(child, Indicator) and self.validate_indicator(child)
        ]

    def _evaluate_logic(self,
        valid_children: List[Union[IndicatorItem, Indicator]],
        indicator: Indicator,
    ) -> bool:
        """Evaluate the logical operator for an indicator."""
        if indicator.operator is Operator.OR:
            return bool(valid_children)
        else:
            return len(valid_children) == len(indicator.items)
