
from typing import List, Dict, Optional, Union, Callable
import os
import winreg as wg
from datetime import datetime as dt, timedelta

from loguru import logger

from scanner.core import BaseHandler
from scanner.models import IndicatorItem, IndicatorItemOperator, IndicatorItemCondition
from scanner.utils import OSType

class RegistryItemHandler(BaseHandler):

    PATH_DELIMITER = r'\\'

    HIVE_NAMES = {
        'HKEY_LOCAL_MACHINE': wg.HKEY_LOCAL_MACHINE,
        'HKEY_CURRENT_CONFIG': wg.HKEY_CURRENT_CONFIG,
        'HKEY_CURRENT_USER': wg.HKEY_CURRENT_USER,
        'HKEY_USERS': wg.HKEY_USERS
    }

    TYPE_MAPPING = {
        wg.REG_BINARY: 'BINARY',
        wg.REG_DWORD: 'DWORD',
        wg.REG_QWORD: 'QWORD',
        wg.REG_LINK: 'LINK',
        wg.REG_SZ: 'TEXT',
        wg.REG_MULTI_SZ: 'TEXT',
        wg.REG_NONE: 'ENCODED',
        wg.REG_RESOURCE_LIST: 'RESOURCE'
    }

    def __init__(self):
        self._registry_cache = {}

    @staticmethod
    def get_supported_terms() -> List[str]:
        return [
            'RegistryItem/Hive',
            'RegistryItem/KeyPath',
            'RegistryItem/Path',
            'RegistryItem/Text',
            'RegistryItem/Type',
            'RegistryItem/Value',
            'RegistryItem/ValueName',
            'RegistryItem/Modified',
            'RegistryItem/NumSubKeys',
            'RegistryItem/NumValues',
            'RegistryItem/ReportedLengthInBytes',
            'RegistryItem/Username',
            # 'RegistryItem/SecurityID', # cant fetch this info using winreg module
        ]

    def _populate_key_info(self, hive: str, key_path: str) -> None:
        try:
            key = self.HIVE_NAMES.get(hive)
            key_handle = wg.OpenKey(key, key_path)
            registry_values = {}

            try:
                subkey_count, num_values, last_modified = wg.QueryInfoKey(key_handle)
                for i in range(num_values):
                    name, data, value_type = wg.EnumValue(key_handle, i)
                    registry_values[name] = {
                        'Hive': hive,
                        'Path': hive + self.PATH_DELIMITER + key_path,
                        'KeyPath': key_path,
                        'ValueName': name,
                        'Value': data,
                        'Type': self.TYPE_MAPPING.get(value_type),
                        'Modified': dt.fromtimestamp(last_modified),
                        'NumValues': str(num_values),
                        'NumSubKeys': subkey_count,
                    }
            except OSError as e:
                logger.error(f'Error while enumerating registry values (key path {key_path}): {str(e)}')
            finally:
                wg.CloseKey(key_handle)

            self._registry_cache[(hive, key_path)] = registry_values
        except FileNotFoundError as e:
            logger.error(f'Registry key not found: {e}')

    def validate(self, items: List[IndicatorItem], operator: IndicatorItemOperator) -> bool:

        # We need to find the KeyPath item that will be used to fetch actual registry branch values
        key_path_item = None
        for item in items:
            term = item.context.search.split('/')[-1]
            if term == 'KeyPath':
                key_path_item = item
                break

        if key_path_item is None:
            logger.info(
                f'Unable to find KeyPath item among the following items: {", ".join([i.id for i in items])}'
            )
            return False

        key_path = key_path_item.content.content
        hive, key_path_parts = key_path.split(self.PATH_DELIMITER)[0]
        if hive not in self.HIVE_NAMES.keys():
            logger.error(
                f'Unknown hive name in KeyPath item: {hive}. Item GUID: {key_path_item.id}'
            )
            return False

        key_path = self.PATH_DELIMITER.join(key_path_parts)
        if (hive, key_path) not in self._registry_cache:
            self._populate_key_info(hive, key_path)


    def get_value_by_term(self, term: str) -> Optional[Union[str, int]]:
        hive, key_path, value_name = term.split('/')
        registry_values = self._registry_cache.get((hive, key_path), {})
        return registry_values.get(value_name, None)

def init():
    return (
        RegistryItemHandler(),
        RegistryItemHandler.get_supported_terms()
    )
