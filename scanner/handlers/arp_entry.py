import ipaddress
import json
import re
import subprocess

from typing import List, Dict, Union, Optional

from scanner.config import ConfigObject
from scanner.core import BaseHandler, ConditionValidator
from scanner.models import IndicatorItem, IndicatorItemOperator as Operator
from scanner.utils import OSType, get_cmd_output

from loguru import logger


class ArpEntryHandler(BaseHandler):

    POWERSHELL_ARP_CMD = 'Get-NetNeighbor'

    IPV4_ADDR_FAMILY_ID = 2
    STORE_PERSISTENT_VAL = 6

    def __init__(self, config):
        self.config = config

    @staticmethod
    def get_supported_terms() -> List[str]:
        return [
            'ArpEntryItem/Interface',
            'ArpEntryItem/PhysicalAddress',
            'ArpEntryItem/CacheType',
            'ArpEntryItem/IPv4Address',
            'ArpEntryItem/IPv6Address',
            # 'ArpEntryItem/IsRouter',
            # 'ArpEntryItem/LastReachable',
            # 'ArpEntryItem/LastUnreachable',
        ]

    def validate(self, items: List[IndicatorItem], operator: Operator) -> bool:
        valid_items = []
        for item in items:
            matched = self._find_matched_arp_entries(item)
            logger.debug(f'Found {len(matched)} matching ARP entries for item {item.id}: {str(matched)}')
            if len(matched) > 0:
                valid_items.append(item)

        return len(valid_items) == len(items) if operator == Operator.AND else bool(valid_items)

    def _find_matched_arp_entries(self, item: IndicatorItem) -> List[IndicatorItem]:
        result = []
        term = item.get_term()
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

    def _fetch_win_arp_entries(self) -> List:
        return self._parse_win_arp_cmd_entries() \
            if self._is_powershell_available() \
            else self._parse_win_arp_cmd_entries()

    def _is_powershell_available(self) -> bool:
        try:
            get_cmd_output(
                f'powershell.exe -Command Get-Command {self.POWERSHELL_ARP_CMD}',
                raise_exceptions=True
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def _fetch_linux_arp_entries(self) -> List:
        cmd_output = self._get_cmd_output(['arp', '-en']).splitlines()
        if len(cmd_output) < 2:
            logger.warning('No data returned from linux "arp" command, skipping output processing...')
            return []

        cmd_output.pop(0)  # remove header

        ret = list()
        for line in cmd_output:
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

            ret.append(entry)
        return ret

    def _determine_cache_type(self, flags: List[str]) -> str:
        if 'M' in flags:
            return 'Dynamic'
        elif 'C' in flags:
            return 'Static'
        else:
            return 'Unknown'

    def _parse_pwrsh_arp_entries(self) -> List[Dict]:
        result = list()
        try:
            cmd = subprocess.run(
                ['powershell.exe', '-Command', self.POWERSHELL_ARP_CMD, '|', 'ConvertTo-Json'],
                capture_output=True, text=True, universal_newlines=True, shell=True
            )
            cmd.check_returncode()
            decoded_data = json.loads(cmd.stdout)
        except subprocess.CalledProcessError as e:
            logger.error('\n'.join([
                f'Failed to fetch ARP table entries from powershell (return code {str(e.returncode)}): {str(e)}',
                f'\tstdout from powershell:\n{str(e.stdout)}',
                f'\tstderr from powershell:\n{str(e.stderr)}'
            ]))
            return result
        except json.JSONDecodeError as e:
            logger.error(f'Error while decoding JSON from Powershell: {str(e)}')
            return result

        for raw_entry in decoded_data:
            entry = dict()

            entry['Interface'] = raw_entry['InterfaceAlias']
            entry['PhysicalAddress'] = raw_entry['LinkStateAddress'].replace('-', ':')
            ip_addr = raw_entry['IPAddress']
            if raw_entry['AddressFamily'] == self.IPV4_ADDR_FAMILY_ID:
                entry['IPv4Address'] = ip_addr
            else:
                entry['IPv6Address'] = ip_addr

            entry['CacheType'] = 'Persistent' if raw_entry['Store'] == self.STORE_PERSISTENT_VAL else 'Active'

            result.append(entry)

        return result

    def _parse_win_arp_cmd_entries(self):
        result = list()

        cmd_output = self._get_cmd_output(['arp', '-a'])
        matches = re.findall(
            r'(?P<addr>[-.:0-9]+)\s+(?P<hwaddr>[-0-9a-f]{17})\s+(?P<type>\w+)',
            cmd_output
        )
        if not matches:
            logger.warning('No data returned from win "arp -a" command, nothing to process...')
            return result

        for match in matches:
            entry = dict()
            entry['PhysicalAddress'] = match[1]
            ip_addr = match[0]
            if ipaddress.ip_address(ip_addr).version == 4:
                entry['IPv4Address'] = ip_addr
            else:
                entry['IPv6Address'] = ip_addr

            entry['CacheType'] = match[2]

            result.append(entry)

        return result


    def _get_cmd_output(self, cmd: List[str]) -> str:
        try:
            run_result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                universal_newlines=True,
                shell=True,
                timeout=10
            )
            run_result.check_returncode()
            return run_result.stdout
        except subprocess.CalledProcessError as e:
            logger.error('\n'.join([
                f'Failed to execute shell command : {str(e)}',
                f'stdout: {e.stdout}',
                f'stderr: {e.stderr}',
            ]))
            return ''
        except subprocess.TimeoutExpired as e:
            logger.error(f'Timeout while executing shell command: {str(e)}')
            return ''



def init(config: ConfigObject):
    return ArpEntryHandler(config)
