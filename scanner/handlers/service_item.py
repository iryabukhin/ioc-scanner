import hashlib
import os
import psutil
import json
from typing import Optional, Union

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
    SIGNATURE_STATUS_NOT_TRUSTED = 4
    SIGNATURE_STATUS_FILE_FORMAT_ERROR = 5

    AUTHENTICODE_SIGNATURE_CMD = 'Get-AuthenticodeSignature'

    # taken from System.Management.Automation.SignatureStatus
    SIGNATURE_STATUS_VALUE_MAP = {
        SIGNATURE_STATUS_VALID: True,  # Valid
        SIGNATURE_STATUS_NOT_SIGNED: False,  # UnknownError
        SIGNATURE_STATUS_NOT_TRUSTED: False,  # NotTrusted,
        SIGNATURE_STATUS_FILE_FORMAT_ERROR: False,  # NotSupportedFileFormat
    }

    def __init__(self, config: ConfigObject):
        super().__init__(config)

        self._lazy_evaluation = self.config.get('lazy_evaluation', False)
        self._service_cache = {}

        config = self.config.get('service_item', {})
        self._scan_executable_signature = config.get('scan_executable_signature') or False
        self._scan_dlls = config.get('scan_dlls') or False
        self._scan_dll_signatures = config.get('scan_dll_signatures') or False

    @staticmethod
    def get_supported_terms() -> list[str]:
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
            try:
                info = {
                    'name': service.name(),
                    'descriptiveName': service.display_name(),
                    'description': service.description(),
                    'path': service.binpath().split(' ')[0] if service.binpath() else None,
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

                if info['path'] and self._scan_executable_signature:
                    info.update(self._get_service_executable_hash(info['path']))

                # no need to fetch this info for services that are stared with their own executable file
                if self._scan_dlls and self._is_service_shared(info['path']) and service.pid():
                    for dll_info in self._get_dll_info(service):
                        for k, v in dll_info.items():
                            if k not in info:
                                info[k] = list()
                            info[k].append(v)

                self._service_cache[service.name()] = info
            except (OSError, PermissionError, psutil.AccessDenied) as e:
                logger.error(f'An error prevented fetching info about {service.name()} process: {str(e)}')
                continue

    def _get_service_args(self, service) -> str | None:
        binpath = service.binpath()
        if not binpath:
            return None
        parts = binpath.split(' ')
        if len(parts) < 2:
            return None
        return ' '.join(parts[1:])

    def validate(self, items: list[IndicatorItem], operator: Operator) -> bool:
        if not OSType.is_win():
            # TODO: Figure out what we should do with Windows-only OpenIoC terms
            return True

        if not self._service_cache:
            self._populate_cache()

        valid_items = set()
        for name, service_data in self._get_service_info().items():
            for item in items:
                value = service_data.get(item.term)
                if value is not None and ConditionValidator.validate_condition(item, value):
                    if operator == Operator.OR and self._lazy_evaluation:
                        return True
                    else:
                        valid_items.add(item)

        return  operator == Operator.AND and len(valid_items) == len(items)

    def _get_exec_dll_modules(self, pid: int) -> list[dict[str, str]]:
        logger.info(f'[BEGIN] Fetching loaded DLL info for {pid=}')

        result = list()

        try:
            import win32api, win32process, win32con
        except ImportError as e:
            logger.error(f'Error during import of win32api, win32process, win32con: {str(e)}')
            return result

        try:
            proc_handle = win32api.OpenProcess(
                win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,
                False,
                pid
            )
        except Exception as e:
            logger.warning(f'Error during a call to OpenProcess for {pid=}: {str(e)}')
            return result

        try:
            modlist = win32process.EnumProcessModules(proc_handle)
        except Exception as e:
            logger.warning(f'Error during a call to EnumProcessModules for {pid=}: {str(e)}')
            return result

        for mod in modlist:
            try:
                modname = win32process.GetModuleFileNameEx(proc_handle, mod)
            except Exception as e:
                logger.warning(f'Error during a call to GetModuleFileNameEx for module {mod}: {str(e)}')
                continue

            if modname.endswith('.dll') and os.path.exists(modname):
                dll_data = {
                   'serviceDLL': modname,
                   'serviceDLLmd5sum': calculate_hash(modname, hashlib.md5),
                   'serviceDLLsha1sum': calculate_hash(modname, hashlib.sha1),
                   'serviceDLLsha256sum': calculate_hash(modname, hashlib.sha256),
                }

                dll_data.update(self._get_dll_signature_info(modname))

                result.append(dll_data)

        logger.info(f'[END] Fetching loaded DLL info for {pid=}')
        return result

    def _get_dll_signature_info(self, dll_path: str) -> dict:
        logger.info(f'[BEGIN] Fetching DLL signature info for file {dll_path}')
        result = dict()
        cmd = self.AUTHENTICODE_SIGNATURE_CMD
        output = get_cmd_output(f'powershell.exe -Command "{cmd} \'{dll_path}\' | ConvertTo-Json')
        if not output:
            logger.warning(f'Failed to retrieve DLL signature info for "{dll_path}"')
            return result

        try:
            data = json.loads(output)
        except json.JSONDecodeError as e:
            logger.warning(f'Failed to parse {cmd} for "{dll_path}": {str(e)}')
            return result

        if not data:
            logger.warning(f'Empty Authenticode data for "{dll_path}", nothing to process...')
            return result

        result['serviceDLLSignatureExists'] = int(data['Status']) != self.SIGNATURE_STATUS_NOT_SIGNED
        result['serviceDLLSignatureVerified'] = int(data['Status']) == self.SIGNATURE_STATUS_VALID
        result['serviceDLLSignatureDescription'] = data['StatusMessage']
        result['serviceDLLCertificateIssuer'] = data['SignerCertificate']['IssuerName']['Name'] if 'SignerCertificate' in data else ''
        result['serviceDLLCertificateSubject'] = data['SignerCertificate']['Subject'] if 'SignerCertificate' in data else ''

        logger.info(f'[END] Fetching DLL signature info for file {dll_path}')

        return result


    def _get_dll_info(self, service) -> list[dict[str, str]]:
        proc = psutil.Process(pid=service.pid())
        try:
            return self._get_exec_dll_modules(int(proc.pid))
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
            return []

    def _is_service_shared(self, srvc_binpath: str) -> bool:
        system_root = os.getenv('SystemRoot')
        svchost_path = os.path.join(system_root,'system32', 'svchost.exe')
        # we need to call lower() because system32 dir name is sometimes uppercased
        return srvc_binpath.lower().startswith(svchost_path.lower())

    def _get_service_executable_hash(self, binary_path: str) ->  dict[str, str]:
        result = {
            'pathmd5sum': '',
            'pathsha1sum': '',
            'pathsha256sum': ''
        }

        if not os.path.exists(binary_path):
            return result

        try:
            result['pathmd5sum'] = calculate_hash(binary_path, hashlib.md5)
            result['pathsha1sum'] = calculate_hash(binary_path, hashlib.sha1)
            result['pathsha256sum'] = calculate_hash(binary_path, hashlib.sha256)
        except Exception as e:
            logger.warning(f'Failed to calculate hash of service binary {binary_path}: {str(e)}')
        finally:
            return result

    def _get_service_info(self) -> dict[str, dict]:
        if not self._service_cache:
            self._populate_cache()
        return self._service_cache


def init(config: ConfigObject):
    return ServiceItemHandler(config)