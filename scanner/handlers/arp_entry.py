import ipaddress
from typing import List, Dict, Union, Optional

from scanner.core import BaseHandler, ConditionValidator
from scanner.models import IndicatorItem, IndicatorItemOperator as Operator
from scanner.utils import OSType

import subprocess


class ArpEntryHandler(BaseHandler):
    @staticmethod
    def get_supported_terms() -> List[str]:
        return [
            'ArpEntryItem/Interface',
            'ArpEntryItem/PhysicalAddress',
            'ArpEntryItem/CacheType',
            'ArpEntryItem/IPv4Address',
            'ArpEntryItem/IPv6Address',
            'ArpEntryItem/PhysicalAddress',
            'ArpEntryItem/IsRouter',
            'ArpEntryItem/LastReachable',
            'ArpEntryItem/LastUnreachable',
        ]

    def validate(self, items: List[IndicatorItem], operator: Operator) -> bool:
        valid_items = []
        for item in items:
            if self._find_matched_arp_entries(item):
                valid_items.append(item)

        return len(valid_items) == len(items) if operator == Operator.AND else bool(valid_items)

    def _find_matched_arp_entries(self, item: IndicatorItem) -> List[IndicatorItem]:
        result = []
        term = item.context.search.split('/')[-1]
        if OSType.is_win():
            output = self._fetch_win_arp_entries()
        elif OSType.is_linux():
            output = self._fetch_linux_arp_entries()
        else:
            return []

        for entry in output:
            value_to_check = entry.get(term)
            if value_to_check is not None and ConditionValidator.validate_condition(item, value_to_check):
                result.append(entry)
        return result

    def _fetch_linux_arp_entries(self) -> List:
        pass

    def _fetch_win_arp_entries(self) -> List:
        run_result = subprocess.run(['arp', '-en'], capture_output=True, text=True, universal_newlines=True)
        run_result.check_returncode()

        output = run_result.stdout.splitlines()
        if len(output) < 2:
            return []

        output.pop(0)  # remove header

        for line in output:
            entry = dict()
            cols = line.split()
            ip_addr = cols[0]
            #  check if it is ipv4 or ipv6
            if ipaddress.ip_address(ip_addr).version == 4:
                entry['IPv4Address'] = ip_addr
            else:
                entry['IPv6Address'] = ip_addr


            entry['PhysicalAddress'] = cols[2].upper()
            entry['Interface'] = cols[4]

            flags = list(cols[3])
            entry['CacheType'] = self._determine_cache_type(flags)

            yield entry

    def _determine_cache_type(self, flags: List[str]) -> str:
        if 'C' in flags:
            return 'Static'
        elif 'R' in flags:
            return 'Dynamic'
        else:
            return 'Unknown'
