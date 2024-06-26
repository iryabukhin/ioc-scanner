import json

from scanner.core import BaseHandler, ConditionValidator
from scanner.models import (
    IndicatorItem,
    IndicatorItemOperator as Operator,
    IndicatorItemCondition as Condition, ValidationResult
)
from scanner.utils import OSType
from scanner.exceptions import UnsupportedOpenIocTerm
from scanner.config import ConfigObject

from loguru import logger

if OSType.is_win():
    import win32evtlog, win32evtlogutil, win32con
    import pywintypes


class EventLogItemHandler(BaseHandler):

    CHANNEL_SYSTEM = 'System'
    CHANNEL_APPLICATION = 'Application'
    CHANNEL_SECURITY = 'Security'

    DEFAULT_CHANNEL = CHANNEL_APPLICATION

    BUF_SIZE = 1024

    EVENT_TYPE_NAMES = {
        win32con.EVENTLOG_AUDIT_FAILURE: 'FailureAudit',
        win32con.EVENTLOG_AUDIT_SUCCESS: 'SuccessAudit',
        win32con.EVENTLOG_INFORMATION_TYPE: 'Information',
        win32con.EVENTLOG_WARNING_TYPE: 'Warning',
        win32con.EVENTLOG_ERROR_TYPE: 'Error'
    }

    def __init__(self, config: ConfigObject):
        super().__init__(config)
        self._log_entry_cache = {}

    @staticmethod
    def get_supported_terms() -> list[str]:
        return [
            'EventLogItem/EID',
            'EventLogItem/log',
            'EventLogItem/message',
            # 'EventLogItem/source',
            'EventLogItem/index',
            'EventLogItem/type',
            # Fetching category name is not supported in pywin32, can only get category number
            # 'EventLogItem/category',
            'EventLogItem/categoryNum',
            # 'EventLogItem/reserved',
            'EventLogItem/machine'
            # 'EventLogItem/CorrelationActivityId',
            # 'EventLogItem/CorrelationRelatedActivityId',
            # 'EventLogItem/blob',
        ]

    def validate(self, items: list[IndicatorItem], operator: Operator) -> ValidationResult:
        result = ValidationResult()

        result.set_lazy_evaluation(self._lazy_evaluation)

        for channel in [self.CHANNEL_APPLICATION, self.CHANNEL_SYSTEM, self.CHANNEL_SECURITY]:

            events = self._fetch_events(channel)

            for item in items:
                event_matches = []
                for event in events:
                    try:
                        is_matched = self._validate_single_item(event, item, channel)
                        if is_matched:
                            result.add_matched_item(item, context={'event': self._format_event_data(event)})
                            if operator == Operator.OR and self._lazy_evaluation:
                                result.skip_remaining_items(items)
                                return result

                    except Exception as e:
                        error_message = f'An error occurred during validation of item: {str(e)}. Event data: {json.dumps(self._format_event_data(event))}'
                        logger.error(error_message)
                        result.add_error_items(item, error_message)

                if operator == operator.AND and all(event_matches):
                    return result

        return result

    def _format_event_data(self, event) -> dict:
        return {
            **{k: getattr(event, k) for k in dir(event) if
               not k.startswith('_') and not isinstance(getattr(event, k), bytes) and not k.startswith('Time')},
            **{k: getattr(event, k).Format() for k in dir(event) if k.startswith('Time')}
        }

    def _fetch_events(self, source_name: str | None = None) -> list:
        ret = list()

        if not source_name:
            source_name = self.DEFAULT_CHANNEL

        logger.debug(f"Fetching events from source: {source_name}")
        handle = None
        try:
            handle = win32evtlog.OpenEventLog(None, source_name)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            offset = 0
            eventlog_records = win32evtlog.ReadEventLog(handle, flags, offset, self.BUF_SIZE)
            while eventlog_records:
                ret.extend(eventlog_records)
                offset += len(eventlog_records)
                eventlog_records = win32evtlog.ReadEventLog(handle, flags, offset, self.BUF_SIZE)
        except Exception as e:
            logger.error(f"Failed to fetch events from '{source_name}' due to an error: {str(e)}")
        finally:
            if handle is not None:
                win32evtlog.CloseEventLog(handle)
        return ret

    def _validate_single_item(self, event, item: IndicatorItem, source: str) -> bool:
        match item.term:
            case 'EID':
                value = int(event.EventID)
            case 'message':
                value = win32evtlogutil.SafeFormatMessage(event, source)
            case 'source':
                value = event.SourceName
            case 'index':
                value = event.RecordNumber
            case 'type':
                value = self.EVENT_TYPE_NAMES.get(event.EventType)
            case 'categoryNum':
                value = event.EventCategory
            case 'log':
                value = source
            case _:
                raise UnsupportedOpenIocTerm(f'Unsupported IOC term: {item.term}')

        result = ConditionValidator.validate_condition(item, value)
        logger.debug(f"Validation result for item '{item.id}' is '{result}'")
        return result


def init(config: ConfigObject):
    return EventLogItemHandler(config)

