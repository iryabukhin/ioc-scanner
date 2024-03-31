import re
from typing import Union, List, Dict, Optional
from datetime import datetime as dt

from scanner.models import IndicatorItem, IndicatorItemCondition as Condition

from loguru import logger

class ConditionValidator:
    @staticmethod
    def validate_condition(
        item: IndicatorItem,
        value_to_check: Union[str, int, float, dt, List]
    ):
        condition = item.condition
        content_type = item.content.type
        content_value = item.content.content

        result = False

        if not item.preserve_case and content_type == 'string':
            value_to_check = value_to_check.lower()
            content_value = content_value.lower()

        if content_type == 'date':
            for var in ['value_to_check', 'content_value']:
                try:
                    locals()[var] = dt.strptime(locals()[var], '%Y-%m-%d') if not isinstance(locals()[var], dt) else locals()[var]
                except ValueError as e:
                    logger.error(f'Failed converting {var} to datetime: {str(e)}')
                    return False

        if condition == Condition.IS:
            result = (value_to_check == content_value)
        elif condition == Condition.CONTAINS and content_type == 'string':
            result = (content_value in value_to_check)
        elif condition == Condition.MATCHES and content_type == 'string':
            result = bool(re.match(content_value, value_to_check))
        elif condition == Condition.STARTS_WITH and content_type == 'string':
            result = value_to_check.startswith(content_value)
        elif condition == Condition.ENDS_WITH and content_type == 'string':
            result = value_to_check.endswith(content_value)
        elif condition == Condition.GREATER_THAN:
            if content_type == 'date':
                result = value_to_check > content_value
            elif content_type in ['int', 'duration']:
                result = int(value_to_check) > int(content_value)
        elif condition == Condition.LESS_THAN:
            if content_type == 'date':
                result = value_to_check < content_value
            elif content_type in ['int', 'duration']:
                result = int(value_to_check) < int(content_value)

        return not result if item.negate else result
