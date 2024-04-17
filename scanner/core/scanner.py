import importlib
import itertools
import os
from operator import attrgetter

from loguru import logger

from scanner.config import ConfigObject
from scanner.exceptions import UnsupportedOpenIocTerm

from scanner.core import BaseHandler
from scanner.models import (
    Indicator,
    IndicatorItem,
    IndicatorItemOperator as Operator,
)

class IOCScanner:
    lazy_evaluation = False
    scanned_iocs = {}
    handlers: dict[str, BaseHandler] = {}

    def __init__(self, config: ConfigObject):
        self.config = config
        self.ignore_unsupported_terms = self.config.get('ignore_unsupported_terms', True)
        if not IOCScanner.handlers:
            self.__init_handlers()

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


    def process(self, indicators: list[Indicator]):
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

    def _validate_indicator_items(self, indicator: Indicator) -> list[IndicatorItem]:
        logger.debug(f'Validating indicator items for indicator: {indicator.id}')
        child_items = [i for i in indicator.items if isinstance(i, IndicatorItem)]
        if not child_items:
            logger.debug(f'No child items found for indicator {indicator.id}...')
            return []

        valid_items = []
        child_items.sort(key=attrgetter('context.document'))
        for item_type, grouped_items in itertools.groupby(child_items, key=attrgetter('context.document')):
            grouped_items = list(grouped_items)
            unsupported_items = {i.id: i for i in grouped_items if i.context.search not in self.handlers.keys()}
            supported_items = {i.id: i for i in grouped_items if i.id not in unsupported_items.keys()}
            if len(unsupported_items) > 0 and self.ignore_unsupported_terms:
                logger.warning(
                    f'Ignoring unsupported items found in indicator {indicator.id}: {unsupported_items.values()}'
                )
                valid_items.extend(unsupported_items)
            else:
                raise UnsupportedOpenIocTerm(
                    f'Unsupported items found for indicator {indicator.id}: {unsupported_items.values()}'
                )
            handler = self.handlers.get(item_type, None)
            if handler.validate(supported_items.values(), indicator.operator):
                valid_items.extend(supported_items.values())

        logger.debug(f'Valid items count for indicator {indicator.id}: {len(valid_items)} out of {len(child_items)}')
        return valid_items

    def _validate_child_indicators(self, indicator: Indicator) -> list[Indicator]:
        logger.debug(f'Validating child indicators for indicator: {indicator.id}')
        children = [i for i in indicator.items if isinstance(i, Indicator)]
        if len(children) == 0:
            logger.debug(f'No child indicators found for indicator {indicator.id}...')
            return []

        valid_children = [i for i in children if self.validate_indicator(i)]
        logger.debug(f'Valid child indicators count for indicator {indicator.id}: {len(valid_children)} out of {len(children)}')
        return valid_children

    def _evaluate_logic(self, valid_children: list[IndicatorItem | Indicator], indicator: Indicator) -> bool:
        logger.debug(f'Evaluating logic for indicator: {indicator.id}')
        if indicator.operator is Operator.OR:
            result = bool(valid_children)
        else:
            result = len(valid_children) == len(indicator.items)
        logger.debug(f'Logic evaluation result for indicator {indicator.id}: {result}')
        return result