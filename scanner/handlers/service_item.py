import hashlib
import os
import psutil
import json
from typing import List, Dict, Optional, Union

from scanner.config import ConfigObject
from scanner.core import BaseHandler
from scanner.core.conditions import ConditionValidator
from scanner.models import (
    IndicatorItem,
    IndicatorItemOperator as Operator,
    IndicatorItemCondition as Condition
)
from scanner.utils import OSType, get_cmd_output

from loguru import logger

from scanner.utils.hash import calculate_hash


class ServiceItemHandler(BaseHandler):

    SIGNATURE_STATUS_VALID = 0
    SIGNATURE_STATUS_NOT_SIGNED = 2

    # taken from System.Management.Automation.SignatureStatus
    SIGNATURE_STATUS_VALUE_MAP = {
        0: True,  # Valid
        SIGNATURE_STATUS_NOT_SIGNED: False,  # UnknownError
        2: False,  # NotSigned,
        4: False,  # NotTrusted,
        5: False,  # NotSupportedFileFormat
    }

    def __init__(self, config: ConfigObject):
        super().__init__()
        self.config = config
        self._service_cache = {}

        self._scan_executable_signature = config.service_item.scan_executable_signature or False
        self._scan_dlls = config.service_item.scan_dlls or False
        self._scan_dll_signatures = config.service_item.scan_dll_signatures or False

    @staticmethod
    def get_supported_terms() -> List[str]:
        return [
            'ServiceItem/arguments',
            'ServiceItem/description',
            'ServiceItem/descriptiveName',
            'ServiceItem/mode',
            'ServiceItem/name',
            'ServiceItem/path',
            'ServiceItem/pathmd5sum',
            'ServiceItem/pathsha1sum',
            'ServiceItem/pathsha256sum',
            'ServiceItem/pid',
            'ServiceItem/serviceDLL',
            'ServiceItem/serviceDLLmd5sum',
            'ServiceItem/serviceDLLsha1sum',
            'ServiceItem/serviceDLLsha256sum',
            'ServiceItem/serviceDLLSignatureDescription'
            'ServiceItem/serviceDLLSignatureExists'
            'ServiceItem/serviceDLLSignatureVerified'
            'ServiceItem/serviceDLLCertificateIssuer'
            'ServiceItem/serviceDLLCertificateSubject'
            'ServiceItem/startedAs',
            'ServiceItem/status',
            'ServiceItem/type'
        ]

    def _populate_cache(self) -> None:
        for service in psutil.win_service_iter():
            info = {
                'name': service.name(),
                'descriptiveName': service.display_name(),
                'description': service.description(),
                'path': service.binpath(),
                'pathmd5sum': calculate_hash(service.binpath(), hashlib.md5),
                'pid': service.pid(),
                'arguments': self._get_service_args(service),
                'status': service.status(),
                'mode': service.start_type(),
                'startedAs': service.username(),
                'serviceDLL': list(),
                'serviceDLLmd5sum': list(),
                'serviceDLLsha1sum': list(),
                'serviceDLLsha256sum': list(),

            }
            # no need to fetch this info for services that are stared with their own executable file
            if self._scan_dlls and self._is_service_shared(service) and service.pid():
                for dll_info in self._get_dll_info(service):
                    info['serviceDLL'].append(dll_info['serviceDLL'])
                    info['serviceDLLmd5sum'].append(dll_info['serviceDLLmd5sum'])
            self._service_cache[service.name()] = info

    def _get_service_args(self, service):
        if not service.pid():
            return ''
        cmdline = psutil.Process(pid=service.pid()).cmdline()
        return cmdline[1:] if len(cmdline) > 1 else ''

    def validate(self, items: List[IndicatorItem], operator: Operator) -> bool:
        if not OSType.is_win():
            # TODO: Figure out what we should do with Windows-only OpenIoC terms
            return True

        if not self._service_cache:
            self._populate_cache()

        valid_items = []
        for item in items:
            if self._find_matched_services(item):
                valid_items.append(item)

        return len(valid_items) == len(items) if operator == Operator.AND else bool(valid_items)

    def _find_matched_services(self, item: IndicatorItem) -> List[IndicatorItem]:
        result = list()
        term = item.context.search.split('/')[-1]
        for service in self._service_cache:
            value_to_check = service.get(term)
            if value_to_check is not None and ConditionValidator.validate_condition(item, value_to_check):
                result.append(service)
        return result

    def _get_exec_dll_modules(self, pid: int) -> List:
        import win32api, win32process, win32con

        result = list()
        try:
            proc_handle = win32api.OpenProcess(
                win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,
                False,
                pid
            )
        except Exception as e:
            logger.warning(f'Error during OpenProcess for {pid=}: {str(e)}')
            return result

        try:
            modlist = win32process.EnumProcessModules(proc_handle)
        except Exception as e:
            logger.warning(f'Error during EnumProcessModules for {pid=}: {str(e)}')
            return result

        for mod in modlist:
            try:
                modname = win32process.GetModuleFileNameEx(proc_handle, mod)
            except Exception as e:
                logger.warning(f'Error during GetModuleFileNameEx for module {mod}: {str(e)}')
                continue

            if modname.endswith('.dll') and os.path.exists(modname):
                result.append({
                   'serviceDLL': modname,
                   'serviceDLLmd5sum': calculate_hash(modname, hashlib.md5)
                })

        return result

    def _get_dll_signature_info(self, dll_path: str) -> Dict:
        result = dict()
        cmd = 'Get-AuthenticodeSignature'
        output = get_cmd_output(
            f'powershell.exe -Command "{cmd} \'{dll_path}\' | ConvertTo-Json'
        )
        if not output:
            logger.warning(f'Failed to retrieve DLL signature info for "{dll_path}"')
            return result

        try:
            signature_data = json.loads(output)
        except json.JSONDecodeError as e:
            logger.warning(f'Failed to parse {cmd} for "{dll_path}": {str(e)}')
            return result

        if not signature_data:
            logger.warning(f'Empty Authenticode data for "{dll_path}", nothing to process...')
            return result

        result['serviceDLLSignatureExists'] = int(signature_data['Status']) != self.SIGNATURE_STATUS_NOT_SIGNED
        result['serviceDLLSignatureVerified'] = int(signature_data['Status']) == self.SIGNATURE_STATUS_VALID
        result['serviceDLLSignatureDescription'] = signature_data['StatusMessage']
        result['serviceDLLCertificateIssuer'] = signature_data['SignerCertificate']['IssuerName']['Name']
        result['serviceDLLCertificateSubject'] = signature_data['SignerCertificate']['Subject']

        return result


    def _get_dll_info(self, service) -> List[Dict[str]]:
        result = list()
        proc = psutil.Process(pid=service.pid())
        try:
            # TODO: Perhaps there is a better way to do this?
            for m in self._get_exec_dll_modules(proc.pid):
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
                f'Unknown error occurred while retrieving DLL info for process {proc.name()} (pid {str(proc.pid)}): {str(e)}'
            )
        finally:
            return result

    def _is_service_shared(self, srvc) -> bool:
        system_root = os.getenv('SystemRoot')
        svchost_path = os.path.join(system_root,' system32', 'svchost.exe')
        # we need to call lower() because system32 dir name is sometimes uppercased
        return srvc.binpath().lower().startswith(svchost_path.lower())


def init(config: ConfigObject):
    return ServiceItemHandler(config)