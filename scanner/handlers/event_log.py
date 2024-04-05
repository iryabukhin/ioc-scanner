
import os
from typing import List, Dict, Union, AnyStr, Optional
from lxml import objectify
from datetime import datetime as dt, timezone as tz

from scanner.core import BaseHandler, ConditionValidator
from scanner.models import (
    IndicatorItem,
    IndicatorItemOperator as Operator,
    IndicatorItemCondition as Condition, IndicatorItemOperator
)
from scanner.utils import OSType
from scanner.config import ConfigObject

from loguru import logger

import xml.etree.ElementTree as ET

if OSType.is_win():
    import win32evtlog, win32evtlogutil, win32con
    import pywintypes



class EventLogItemHandler(BaseHandler):

    CHANNEL_SYSTEM = 'System'
    CHANNEL_APPLICATION = 'Application'
    CHANNEL_SECURITY = 'Security'

    evt_dict = {
        win32con.EVENTLOG_AUDIT_FAILURE: 'FailureAudit',
        win32con.EVENTLOG_AUDIT_SUCCESS: 'SucessAudit',
        win32con.EVENTLOG_INFORMATION_TYPE: 'Information',
        win32con.EVENTLOG_WARNING_TYPE: 'Warning',
        win32con.EVENTLOG_ERROR_TYPE: 'Error'
    }

    def __init__(self, config: ConfigObject):
        self.config = config
        self._log_entry_cache = {}

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
            'EventLogItem/machine'
            'EventLogItem/CorrelationActivityId',
            'EventLogItem/CorrelationRelatedActivityId',
            'EventLogItem/blob',
        ]

    def validate(self, items: List[IndicatorItem], operator: IndicatorItemOperator) -> bool:
        fetched_events = self._fetch_events(self.CHANNEL_SYSTEM)
        filter_function = all if IndicatorItemOperator is IndicatorItemOperator.AND else any
        return filter_function(self._validate_item(event, items) for event in fetched_events)


    def _fetch_events(self, chanel: str, start_time: dt, end_time: dt):
        handle = win32evtlog.OpenEventLog(None, chanel)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = win32evtlog.ReadEventLog(handle, flags, 0)
        win32evtlog.CloseEventLog(handle)
        return events


    def _validate_item(self, event, items):
        for item in items:
            if not self._validate_single_item(event, item):
                return False
        return True

    def _validate_single_item(self, event, item: IndicatorItem, chanel: str) -> bool:
        # Extract relevant data from the fetched events
        # Compare the extracted data with the conditions specified in the IndicatorItem
        if item.get_term() == 'EID':
            value = int(event.EventID)
        elif item.get_term() == 'message':
            value = win32evtlogutil.SafeFormatMessage(event, chanel)
        elif item.get_term() == 'source':
            # Example: Check if Source matches the specified value
            value = event.SourceName
        elif item.get_term() == 'machine':
            value = event.ComputerName
        elif item.get_term() == 'type':
            value = self.evt_dict[event.EventType]
        elif item.get_term() == 'categoryNum':
            value  = event.EventCategory

        return ConditionValidator.validate_condition(item, value)



def init(config: ConfigObject):
    return EventLogItemHandler(config)

