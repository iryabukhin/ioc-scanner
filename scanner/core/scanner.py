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
    OpenIOCScanResult,
    IndicatorScanResult,
    ValidationResult as ItemsValidationResult
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

    def process(self, indicators: list[Indicator]) -> OpenIOCScanResult:
        logger.info(f'Processing a total of {len(indicators)} indicators...')

        overall_valid = False
        matches = []
        for indicator in indicators:
            validation_result = self._validate_indicator(indicator)
            matches.append(
                {
                    'id': indicator.id,
                    'operator': indicator.operator,
                    'valid_items': [self._build_valid_item_data(i, validation_result) for i in validation_result.valid_items],
                    'skipped_items': [i.id for i in validation_result.skipped_items]
                }
            )

        return OpenIOCScanResult(
            result=overall_valid,
            matches=matches
        )

    def _validate_indicator(self, indicator: Indicator) -> IndicatorScanResult:
        logger.debug(f'Validating indicator: {indicator.id}')
        if not IOCScanner.handlers:
            logger.error('No handlers have been loaded!')
            raise Exception('No handlers have been loaded!')

        result = IndicatorScanResult.from_indicator_object(indicator)

        items_validation_result = self._validate_indicator_items(indicator)
        for item in items_validation_result.matched_items:
            result.add_valid_item(item)

        for item in items_validation_result.skipped_items:
            result.add_skipped_item(item)

        for item in items_validation_result.error_items:
            result.add_error_item(item)

        for item_id, data in items_validation_result.item_context:
            result.match_data[item_id] = data

        for child in indicator.child_indicators:
            result.merge(self._validate_indicator(child))

        result.update_valid_status()

        return result

    def _validate_indicator_items(self, indicator: Indicator) -> ItemsValidationResult:
        logger.debug(f'Validating indicator items for indicator: {indicator.id}')

        result = ItemsValidationResult()
        child_items = [i for i in indicator.children if isinstance(i, IndicatorItem)]
        if not child_items:
            logger.debug(f'No child items found for indicator {indicator.id}...')
            return result

        child_items.sort(key=attrgetter('context.document'))
        for item_type, items in itertools.groupby(child_items, key=attrgetter('context.document')):
            items = list(items)

            unsupported_items = {i.id: i for i in items if i.context.search not in self.handlers.keys()}
            supported_items = {i.id: i for i in items if i.id not in unsupported_items.keys()}

            result.add_skipped_items(list(unsupported_items.values()))

            items = list(supported_items.values())
            handler = self.handlers.get(items[0].context.search, None)
            validation_result = handler.validate(items, indicator.operator)
            result.merge(validation_result)

        logger.debug(f'Valid items found for indicator {indicator.id}: {len(result.matched_items)} out of {len(child_items)}')

        return result

    def _evaluate_logic(self, valid_children: list[IndicatorItem | Indicator], indicator: Indicator) -> bool:
        logger.debug(f'Evaluating logic for indicator: {indicator.id}')
        if indicator.operator is Operator.OR:
            result = bool(valid_children)
        else:
            result = len(valid_children) == len(indicator.children)
        logger.debug(f'Logic evaluation result for indicator {indicator.id}: {result}')
        return result

    def _build_valid_item_data(self, item: IndicatorItem, validation_result: IndicatorScanResult):
        return {
            'id': item.id,
            'type': item.context.search,
            'match_details': validation_result.match_data.get(item.id, dict())
        }
