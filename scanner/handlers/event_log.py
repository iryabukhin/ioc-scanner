
import os
from typing import List

from scanner.core import BaseHandler, ConditionValidator
from scanner.models import (
    IndicatorItem,
    IndicatorItemOperator as Operator,
    IndicatorItemCondition as Condition, IndicatorItemOperator
)
from scanner.utils import OSType
from scanner.config import ConfigObject

from loguru import logger


class EventLogItemHandler(BaseHandler):

    def __init__(self, config: ConfigObject):
        self.config = config

    def validate(self, items: List[IndicatorItem], operator: IndicatorItemOperator) -> bool:
        pass

    @staticmethod
    def get_supported_terms() -> List[str]:
        return [
            'EventLogItem/EID',
            'EventLogItem/log',
            'EventLogItem/message',
            'EventLogItem/source',
            'EventLogItem/index',
            'EventLogItem/type',
            'EventLogItem/category',
            'EventLogItem/categoryNum',
            'EventLogItem/reserved',
            'EventLogItem/CorrelationActivityId',
            'EventLogItem/CorrelationRelatedActivityId',
            'EventLogItem/blob',
        ]


def init(config: ConfigObject):
    return EventLogItemHandler(config)
