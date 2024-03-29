
from typing import List, Dict, Optional, Union, Callable
import os
import winreg as wg

from scanner.config import ConfigObject
from scanner.core import BaseHandler, ConditionValidator
from scanner.models import IndicatorItem, IndicatorItemOperator as Operator
from scanner.utils import OSType, from_windows_timestamp

from loguru import logger


class RegistryItemHandler(BaseHandler):

    PATH_DELIMITER = r'\\'

    HIVES = {
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

    def __init__(self,  config: ConfigObject):
        self.config = config
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
            key = self.HIVES.get(hive)
            key_handle = wg.OpenKey(key, key_path)
            registry_values = {}

            full_key_path = self.PATH_DELIMITER.join([hive, key_path])

            try:
                subkey_count, num_values, last_modified = wg.QueryInfoKey(key_handle)
                for i in range(num_values):
                    value_name, raw_data, value_type = wg.EnumValue(key_handle, i)
                    registry_values[value_name] = {
                        'Hive': hive,
                        'Path': full_key_path,
                        'KeyPath': key_path,
                        'ValueName': value_name,
                        'Value': raw_data,
                        'Text': raw_data,
                        'Type': self.TYPE_MAPPING.get(value_type),
                        'Modified': from_windows_timestamp(last_modified),
                        'NumValues': num_values,
                        'NumSubKeys': subkey_count,
                        'ReportedLengthInBytes': len(raw_data.encode()) if isinstance(raw_data, str) else (raw_data.bit_length() + 7) // 8,
                    }
            except OSError as e:
                logger.error(
                    f'OSError while enumerating registry values (key path "{key_path}"): {str(e)}'
                )
            except Exception as e:
                logger.error(
                    f'An unknown error occurred while processing registry values (key path "{key_path}"): {str(e)}'
                )
            finally:
                wg.CloseKey(key_handle)

            self._registry_cache[(hive, key_path)] = registry_values
        except FileNotFoundError as e:
            logger.error(f'Registry key not found: {e}')

    def validate(self, items: List[IndicatorItem], operator: Operator) -> bool:
        # TOOO: figure out how to handle items that are not supported for the give OS
        if not OSType.is_win():
            return False

        # We need to find the KeyPath item that will be used to fetch actual registry branch values
        key_path_item = next(
            (i for i in items if i.context.search.endswith('KeyPath')),
            None
        )

        if key_path_item is None:
            logger.info(
                f'Unable to find KeyPath item among the following items: {", ".join([i.id for i in items])}'
            )
            return False

        key_path = key_path_item.content.content
        hive, *key_path_parts = key_path.split(self.PATH_DELIMITER)
        if hive not in self.HIVES:
            logger.error(
                f'Unsupported hive name in KeyPath item: "{hive}". Item GUID: "{key_path_item.id}"'
            )
            return False

        key_path = self.PATH_DELIMITER.join(key_path_parts)
        if (hive, key_path) not in self._registry_cache:
            self._populate_key_info(hive, key_path)

        valid_items = list()
        key_values = self._registry_cache.get((hive, key_path))
        for item in items:
            term = item.context.search.split('/')[-1]
            for value_name, value in key_values.items():
                value_to_check = value.get(term)
                if value_to_check is not None and ConditionValidator.validate_condition(item, value_to_check):
                    valid_items.append(value)

        return len(valid_items) == len(items) if operator == Operator.AND else bool(valid_items)


def init(config: ConfigObject):
    return RegistryItemHandler(config)
