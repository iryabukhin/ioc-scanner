import importlib
import itertools
import os
from operator import attrgetter
from typing import List, Dict, Union, Optional

from loguru import logger

from scanner.config import ConfigObject
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
    handlers_by_type: Dict[str, BaseHandler] = {}  # optimized handler lookup

    def __init__(self, config: ConfigObject):
        self.config = config
        logger.info('Initializing IOCScanner...')
        if not IOCScanner.handlers:
            self.__init_handlers()
            self.__organize_handlers_by_type()

    def __init_handlers(self):
        logger.info('Initializing handlers...')
        handlers_dir = os.getenv(
            'HANDLERS_BASE_DIR',
            os.path.join(os.path.dirname(os.path.dirname(__file__)), 'handlers')
        )
        for fname in os.listdir(handlers_dir):
            if fname.endswith('.py') and fname != '__init__.py':
                module_name = fname[:-3]
                try:
                    module = importlib.import_module(f'scanner.handlers.{module_name}')
                    if not hasattr(module, 'init') or not callable(module.init):
                        logger.error(f'Handler {module_name} does not implement init() method, skipping initialization...')
                        continue
                    handler = module.init(config=self.config)
                    if not isinstance(handler, BaseHandler):
                        logger.error(f'Handler {module_name} does not implement BaseHandler interface, skipping initialization...')
                        continue
                    logger.info(f'Successfully initialized handler: {module_name}')
                    IOCScanner.handlers.update({t: handler for t in handler.get_supported_terms()})
                except ImportError as e:
                    logger.error(f'Unable to import module {fname}: {e}')
                except Exception as e:
                    logger.error(f'Error loading handler from module {fname}: {e}')

    def __organize_handlers_by_type(self):
        for term, handler in IOCScanner.handlers.items():
            item_type = term.split('/')[0]
            IOCScanner.handlers_by_type[item_type] = handler

    def process(self, indicators: List[Indicator]):
        logger.info(f'Processing {len(indicators)} indicators...')
        processed_ids = [i.id for i in indicators if self.validate_indicator(i)]
        logger.info(f'Processed indicators. Valid indicators: {len(processed_ids)}')
        return processed_ids

    def validate_indicator(self, indicator: Indicator) -> bool:
        logger.debug(f'Validating indicator: {indicator.id}')
        if not IOCScanner.handlers:
            logger.error('No handlers have been loaded!')
            raise Exception('No handlers have been loaded!')

        valid_children = (
            self._validate_indicator_items(indicator)
            + self._validate_child_indicators(indicator)
        )

        result = self._evaluate_logic(valid_children, indicator)
        logger.debug(f'Indicator {indicator.id} validation result: {result}')
        return result

    def _validate_indicator_items(self, indicator: Indicator) -> List[IndicatorItem]:
        logger.debug(f'Validating indicator items for indicator: {indicator.id}')
        valid_items = []
        child_items = [i for i in indicator.items if isinstance(i, IndicatorItem)]
        if len(child_items) == 0:
            logger.debug(f'No child items found for indicator {indicator.id}...')
            return valid_items

        for item_type, items in itertools.groupby(child_items, key=attrgetter('context.document')):
            items = [i for i in items]
            handler = IOCScanner.handlers_by_type.get(item_type)
            if not handler:
                logger.warning(f'Unknown data type: {item_type}')
                raise UnsupportedOpenIocTerm(f'Unknown data type: {item_type}')
            if handler.validate(items, indicator.operator):
                valid_items.extend(items)
        logger.debug(f'Valid items count for indicator {indicator.id}: {len(valid_items)} out of {len(child_items)}')
        return valid_items

    def _validate_child_indicators(self, indicator: Indicator) -> List[Indicator]:
        logger.debug(f'Validating child indicators for indicator: {indicator.id}')
        children = [i for i in indicator.items if isinstance(i, Indicator)]
        if len(children) == 0:
            logger.debug(f'No child indicators found for indicator {indicator.id}...')
            return []

        valid_children = [i for i in children if self.validate_indicator(i)]
        logger.debug(f'Valid child indicators count for indicator {indicator.id}: {len(valid_children)} out of {len(children)}')
        return valid_children

    def _evaluate_logic(self, valid_children: List[Union[IndicatorItem, Indicator]], indicator: Indicator) -> bool:
        logger.debug(f'Evaluating logic for indicator: {indicator.id}')
        if indicator.operator is Operator.OR:
            result = bool(valid_children)
        else:
            result = len(valid_children) == len(indicator.items)
        logger.debug(f'Logic evaluation result for indicator {indicator.id}: {result}')
        return result