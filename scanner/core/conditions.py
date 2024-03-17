import re
from typing import Union
from datetime import datetime

from scanner.models import IndicatorItem, IndicatorItemCondition


class ConditionValidator:
    @staticmethod
    def validate_condition(
            item: IndicatorItem,
            value_to_check: Union[str, int, float, datetime]
    ):
        condition = item.condition
        content_type = item.content.type
        content_value = item.content.content
        preserve_case = item.preserve_case
        negate = item.negate

        if not preserve_case and content_type == 'string':
            value_to_check = value_to_check.lower()
            content_value = content_value.lower()

        result = False

        if condition == IndicatorItemCondition.IS:
            result = (value_to_check == content_value)
        elif condition == IndicatorItemCondition.CONTAINS and content_type == 'string':
            result = (content_value in value_to_check)
        elif condition == IndicatorItemCondition.MATCHES and content_type == 'string':
            result = bool(re.match(content_value, value_to_check))
        elif condition == IndicatorItemCondition.STARTS_WITH and content_type == 'string':
            result = value_to_check.startswith(content_value)
        elif condition == IndicatorItemCondition.ENDS_WITH and content_type == 'string':
            result = value_to_check.endswith(content_value)
        elif condition == IndicatorItemCondition.GREATER_THAN:
            if content_type == 'date':
                result = datetime.strptime(value_to_check, '%Y-%m-%d') > datetime.strptime(content_value, '%Y-%m-%d')
            elif content_type in ['int', 'duration']:
                result = int(value_to_check) > int(content_value)
        elif condition == IndicatorItemCondition.LESS_THAN:
            if content_type == 'date':
                result = datetime.strptime(value_to_check, '%Y-%m-%d') < datetime.strptime(content_value, '%Y-%m-%d')
            elif content_type in ['int', 'duration']:
                result = int(value_to_check) < int(content_value)

        return not result if negate else result
