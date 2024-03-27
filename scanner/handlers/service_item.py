import hashlib
import os
import psutil
from typing import List, Dict, Optional, Union

from scanner.core import BaseHandler
from scanner.core.conditions import ConditionValidator
from scanner.models import (
    IndicatorItem,
    IndicatorItemOperator as Operator,
    IndicatorItemCondition as Condition
)
from scanner.utils import OSType

from loguru import logger

from scanner.utils.hash import calculate_hash


class ServiceItemHandler(BaseHandler):
    def __init__(self):
        super().__init__()
        self.service_cache = {}

    @staticmethod
    def get_supported_terms() -> List[str]:
        return [
            'ServiceItem/arguments',
            'ServiceItem/description',
            'ServiceItem/descriptiveName',
            'ServiceItem/mode',
            'ServiceItem/name',
            'ServiceItem/path',
            'ServiceItem/pid',
            'ServiceItem/serviceDLL',  # unsupported as of now
            'ServiceItem/serviceDLLmd5sum',
            'ServiceItem/startedAs',
            'ServiceItem/status',
            'ServiceItem/type'
        ]

    def _populate_cache(self) -> None:
        for service in psutil.win_service_iter():
            dll_info = self._get_dll_info(service)
            info = {
                'name': service.name(),
                'descriptiveName': service.display_name(),
                'description': service.description(),
                'path': service.binpath(),
                'pid': service.pid(),
                'arguments': self._get_service_args(service),
                'status': service.status(),
                'mode': service.start_type(),
                'startedAs': service.username(),
                'serviceDLL': dll_info['serviceDLL'],
                'serviceDLLmd5sum': dll_info['serviceDLLmd5sum'],
            }

            self.service_cache[service.name()] = info

    def _get_service_args(self, service):
        if not service.pid():
            return ''
        cmdline = psutil.Process(pid=service.pid()).cmdline()
        return cmdline[1:] if len(cmdline) > 1 else ''

    def validate(self, items: List[IndicatorItem], operator: Operator) -> bool:
        if not OSType.is_win():
            # TODO: Figure out what we should do with Windows-only OpenIoC terms
            return True

        if not self.service_cache:
            self._populate_cache()

        valid_items = []
        for item in items:
            if self._find_matched_services(item):
                valid_items.append(item)

        return len(valid_items) == len(items) if operator == Operator.AND else bool(valid_items)

    def _find_matched_services(self, item: IndicatorItem) -> List[IndicatorItem]:
        result = list()
        term = item.context.search.split('/')[-1]
        for service in self.service_cache:
            value_to_check = service.get(term)
            if value_to_check is not None and ConditionValidator.validate_condition(item, value_to_check):
                result.append(service)
        return result

    def _get_dll_info(self, service) -> List:
        result = list()

        if not service.pid():
            return result

        proc = psutil.Process(pid=service.pid())
        try:
            # TODO: Perhaps there is a better way to do this?
            for m in proc.memory_maps(grouped=True):
                if m.path.endswith('.dll'):
                    result.append({
                       'serviceDLL': m.path,
                       'serviceDLLmd5sum': calculate_hash(m.path, hashlib.md5)
                    })
        except PermissionError as e:
            logger.error(
                f'Permission error occurred while retrieving DLL info for process {proc.name()} (pid {str(proc.pid)}): {str(e)}'
            )
        except psutil.NoSuchProcess as e:
            logger.error(
                f'Process {proc.name()} (pid {str(proc.pid)}) does not exist: {str(e)}'
            )
        except Exception as e:
            logger.error(
                f'Uknown error occurred while retrieving DLL info for process {proc.name()} (pid {str(proc.pid)}): {str(e)}'
            )
        finally:
            return result


def init():
    return (
        ServiceItemHandler(),
        ServiceItemHandler.get_supported_terms()
    )