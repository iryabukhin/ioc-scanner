
from typing import Optional, Union, Callable, AnyStr, ByteString
from pathlib import Path

import os
import winreg as wg
from enum import Enum, auto

from scanner.config import ConfigObject
from scanner.core import BaseHandler, ConditionValidator
from scanner.models import IndicatorItem, IndicatorItemOperator as Operator
from scanner.utils import OSType, from_windows_timestamp

from loguru import logger


class RegistryItemHandler(BaseHandler):

    PATH_DELIMITER = '\\'

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
        'HKEY_USERS': wg.HKEY_USERS,
        'HKEY_CLASSES_ROOT': wg.HKEY_CLASSES_ROOT
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
        super().__init__(config)
        self.HIVE_NAMES = {v: k for k, v in  self.HIVES.items()}
        self._lazy_evaluation = config.get('lazy_evaluation', False)
        self._registry_cache = {}

    @staticmethod
    def get_supported_terms() -> list[str]:
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
            if hive is None:
                logger.error(f'Unsupported hive name provided: "{hive}". Path: "{key_path}"')
                return
            with wg.OpenKey(key, key_path) as key_handle:
                registry_values = self._enumerate_key_values(key_handle, hive, key_path)
            self._registry_cache[(hive, key_path)] = registry_values
        except FileNotFoundError as e:
            logger.error(f'Registry key not found: {str(e)}. Key path: {key_path}')

    def _enumerate_key_values(self, key_handle, hive: str, key_path: str) -> Dict:
        registry_values = {}
        subkey_count, num_values, last_modified = wg.QueryInfoKey(key_handle)
        full_key_path = self.PATH_DELIMITER.join([hive, key_path])
        for i in range(num_values):
            value_name, raw_data, value_type = wg.EnumValue(key_handle, i)
            registry_values[value_name] = {
                'Hive': hive,
                'Path': key_path,
                'KeyPath': full_key_path,
                'ValueName': value_name,
                'Value': self._get_registry_value(raw_data, value_type),
                'Text': raw_data,
                'Type': self.TYPE_MAPPING.get(value_type),
                'Modified': from_windows_timestamp(last_modified),
                'NumValues': num_values,
                'NumSubKeys': subkey_count,
                'ReportedLengthInBytes': self._get_value_length(raw_data, value_type),
            }
        return registry_values

    def validate(self, items: list[IndicatorItem], operator: Operator) -> bool:
        if not OSType.is_win():
            return False

        # We need to find the KeyPath item that will be used to fetch actual registry branch values
        key_path_item = next((i for i in items if i.get_term().endswith('KeyPath')), None)

        if key_path_item:
            key_path = key_path_item.content.content
            hive, *key_path_parts = key_path.split(self.PATH_DELIMITER)

            if hive in self.HIVE_ABBREVIATIONS:
                hive = self.HIVE_ABBREVIATIONS[hive]

            if hive not in self.HIVES:
                logger.error(f'Unsupported hive name in KeyPath item: "{hive}". Item GUID: "{key_path_item.id}"')
                return False

            key_path = self.PATH_DELIMITER.join(key_path_parts)
            if (hive, key_path) not in self._registry_cache:
                self._populate_key_info(hive, key_path)

            key_values = self._registry_cache.get((hive, key_path), {})
            valid_items = set()
            for value_name, value_data in sorted(key_values.items()):
                for item in items:
                    value_to_check = value_data.get(item.get_term())
                    if value_to_check is not None and ConditionValidator.validate_condition(item, value_to_check):
                        if operator == Operator.OR:
                            return True
                        else:
                            valid_items.add(item)
            return operator == Operator.AND and len(valid_items) == len(items)
        else:
            # Perform a full scan if no KeyPath item is provided
            logger.info("No KeyPath item provided, engaging full registry scan...")

            specified_hives = [i.content.content for i in items if i.get_term() == 'Hive']
            specified_hives = [self.HIVE_ABBREVIATIONS.get(hive, hive) for hive in specified_hives]
            hives_to_scan = {name: key for name, key in self.HIVES.items() if
                             name in specified_hives or not specified_hives}

            valid_items = set()

            for hive_name, hive_key in hives_to_scan.items():
                for value in self._enumerate_path_values(hive_key):
                    for item in items:
                        if item in valid_items:
                            continue
                        term = item.get_term()
                        value_to_check = value.get(term)
                        if value_to_check is not None and ConditionValidator.validate_condition(item, value_to_check):
                            if operator == operator.OR:
                                return True
                            else:
                                valid_items.add(item)

            return operator == operator.AND and len(valid_items) == len(items)


    def _enumerate_path_values(self, hive_key: int, path: str = ''):
        try:
            with wg.OpenKey(hive_key, path) as key_handle:
                subkey_count, num_values, _ = wg.QueryInfoKey(key_handle)
                for i in range(num_values):
                    value_name, raw_data, value_type = wg.EnumValue(key_handle, i)
                    processed_value = self._get_registry_value(raw_data, value_type)
                    hive_name = self.HIVE_NAMES.get(hive_key)
                    full_path = (hive_name + self.PATH_DELIMITER + path) if path else hive_name
                    yield {
                        'Hive': hive_name,
                        'Path': path,
                        'KeyPath': full_path,
                        'ValueName': value_name,
                        'Value': processed_value,
                        'Text': processed_value,
                        'Type': self.TYPE_MAPPING.get(value_type),
                        'Modified': None,
                        'NumValues': num_values,
                        'NumSubKeys': subkey_count,
                        'ReportedLengthInBytes': self._get_value_length(raw_data, value_type),
                    }
                for j in range(subkey_count):
                    subkey_name = wg.EnumKey(key_handle, j)
                    new_path = subkey_name if not path else path + self.PATH_DELIMITER + subkey_name
                    yield from self._enumerate_path_values(hive_key, new_path)
        except FileNotFoundError as e:
            logger.error(f'Registry key not found: {str(e)}. Path: {path}')
        except PermissionError as e:
            logger.error(f'Unable to access registry key due to a permission error: {str(e)}. Path: {path}')

    def _get_registry_value(self, raw_data: Union[str, bytes, int], value_type: int):
        if isinstance(raw_data, bytes) and value_type == wg.REG_BINARY:
            return '0x' + raw_data.hex()
        elif isinstance(raw_data, str):
            return raw_data
        else:
            return str(raw_data)

    def _get_value_length(self, raw_data, value_type: int):
        if value_type == wg.REG_MULTI_SZ and isinstance(raw_data, list):
            return sum(map(lambda v: self._get_value_length(v, wg.REG_SZ), raw_data))
        if value_type == wg.REG_NONE or raw_data is None:
            return 0
        elif isinstance(raw_data, bytes):
            return len(raw_data)
        elif isinstance(raw_data, str):
            return len(raw_data.encode('utf-16le'))
        else:
            return (raw_data.bit_length() + 7) // 8

    def _replace_abbreviated_hive_name(self, path: str) -> str:
        for name in self.HIVE_ABBREVIATIONS:
            if path.startswith(name):
                return path.replace(name, self.HIVE_ABBREVIATIONS[name])
        return path


def init(config: ConfigObject):
    return RegistryItemHandler(config)
