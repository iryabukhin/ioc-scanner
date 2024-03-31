
from typing import List, Dict, Optional, Union, Callable, AnyStr, ByteString
import os
import winreg as wg

from scanner.config import ConfigObject
from scanner.core import BaseHandler, ConditionValidator
from scanner.models import IndicatorItem, IndicatorItemOperator as Operator
from scanner.utils import OSType, from_windows_timestamp

from loguru import logger


class RegistryItemHandler(BaseHandler):

    PATH_DELIMITER = r'\\'

    HIVE_ABBREVIATIONS = {
        'HKLM': 'HKEY_LOCAL_MACHINE',
        'HKCU': 'HKEY_CURRENT_USER',
        'HKCR': 'HKEY_CLASSES_ROOT',
        'HKCC': 'HKEY_CURRENT_CONFIG',
        'HKU': 'HKEY_USERS'
    }

    HIVES = {
        'HKEY_LOCAL_MACHINE': wg.HKEY_LOCAL_MACHINE,
        'HKEY_CURRENT_CONFIG': wg.HKEY_CURRENT_CONFIG,
        'HKEY_CURRENT_USER': wg.HKEY_CURRENT_USER,
        'HKEY_USERS': wg.HKEY_USERS
    }

    TYPE_MAPPING = {
        wg.REG_NONE: 'REG_NONE',
        wg.REG_BINARY: 'REG_BINARY',
        wg.REG_DWORD: 'REG_DWORD',
        wg.REG_QWORD: 'REG_QWORD',
        wg.REG_LINK: 'REG_LINK',
        wg.REG_SZ: 'REG_SZ',
        wg.REG_MULTI_SZ: 'REG_MULTI_SZ',
        wg.REG_RESOURCE_LIST: 'REG_RESOURCE_LIST',
        wg.REG_DWORD_BIG_ENDIAN: 'REG_DWORD_BIG_ENDIAN',
        wg.REG_EXPAND_SZ: 'REG_EXPAND_SZ',
        wg.REG_RESOURCE_REQUIREMENTS_LIST: 'REG_RESOURCE_REQUIREMENTS_LIST',
        wg.REG_FULL_RESOURCE_DESCRIPTOR: 'REG_FULL_RESOURCE_DESCRIPTOR',
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
                        'Value': self._get_registry_value(raw_data, value_type),
                        'Text': raw_data,
                        'Type': self.TYPE_MAPPING.get(value_type),
                        'Modified': from_windows_timestamp(last_modified),
                        'NumValues': num_values,
                        'NumSubKeys': subkey_count,
                        'ReportedLengthInBytes': self._get_value_length(raw_data, value_type),
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
            (i for i in items if i.get_term().endswith('KeyPath')),
            None
        )

        if key_path_item is None:
            logger.info(
                f'Unable to find KeyPath item among the following items: {", ".join([i.id for i in items])}'
            )
            return False

        key_path = key_path_item.content.content
        hive, *key_path_parts = key_path.split(self.PATH_DELIMITER)

        if hive in self.HIVE_ABBREVIATIONS:
            hive = self.HIVE_ABBREVIATIONS[hive]

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

    def _get_registry_value(self, raw_data: Union[str, bytes, int], value_type: int):
        if isinstance(raw_data, bytes) and value_type == wg.REG_BINARY:
            return '0x' + raw_data.hex()
        elif isinstance(raw_data, str):
            return raw_data
        else:
            return str(raw_data)

    def _get_value_length(self, raw_data: Union[str, bytes, int], value_type: int):
        if isinstance(raw_data, bytes):
            return len(raw_data)
        elif isinstance(raw_data, str):
            return len(raw_data.encode('utf-16le'))
        else:
            return (raw_data.bit_length() + 7) // 8


def init(config: ConfigObject):
    return RegistryItemHandler(config)
