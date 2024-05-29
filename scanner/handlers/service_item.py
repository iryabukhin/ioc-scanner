import hashlib
import os
import psutil
import json

from scanner.config import ConfigObject
from scanner.core import BaseHandler
from scanner.core.conditions import ConditionValidator
from scanner.models import (
    IndicatorItem,
    IndicatorItemOperator as Operator,
    IndicatorItemCondition as Condition, ValidationResult
)
from scanner.utils import OSType, get_cmd_output

from loguru import logger

from scanner.utils.hash import calculate_hash

try:
    import win32service
    import win32api
    import win32con
except ImportError:
    pass

class ServiceItemHandler(BaseHandler):
    SIGNATURE_STATUS_VALID = 0
    SIGNATURE_STATUS_NOT_SIGNED = 2
    SIGNATURE_STATUS_NOT_TRUSTED = 4
    SIGNATURE_STATUS_FILE_FORMAT_ERROR = 5

    AUTHENTICODE_SIGNATURE_CMD = 'Get-AuthenticodeSignature'

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
        self._scan_dll_signatures = self._scan_dlls and config.get('scan_dll_signatures', False)

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

    def validate(self, items: list[IndicatorItem], operator: Operator) -> ValidationResult:
        result = ValidationResult()
        self._update_scan_flags(items)

        if not self._service_cache:
            self._populate_cache()

        for name, service_data in self._get_service_info().items():
            for item in items:
                value = service_data.get(item.term)
                if value is not None and ConditionValidator.validate_condition(item, value):
                    result.add_matched_item(item, context={'service': service_data})
                    if operator == Operator.OR and self._lazy_evaluation:
                        result.add_skipped_items(items)
                        return result

        return result

    def _populate_cache(self) -> None:
        try:
            scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)
        except Exception as e:
            logger.error(f'Error opening Service Control Manager: {str(e)}')
            return

        try:
            services = win32service.EnumServicesStatus(scm, win32service.SERVICE_WIN32, win32service.SERVICE_STATE_ALL)
            for service_name, display_name, status in services:
                try:
                    service_handle = win32service.OpenService(scm, service_name, win32con.GENERIC_READ)
                    service_info = win32service.QueryServiceConfig(service_handle)
                    service_status = win32service.QueryServiceStatus(service_handle)

                    info = {
                        'name': service_name,
                        'descriptiveName': display_name,
                        'description': service_info[1],
                        'path': service_info[3].split(' ')[0],
                        'pid': service_status[5],
                        'arguments': self._get_service_args(service_info[3]),
                        'status': self._get_service_status(service_status[1]),
                        'mode': self._get_service_start_type(service_info[0]),
                        'startedAs': '',
                        'serviceDLL': list(),
                        'serviceDLLmd5sum': list(),
                        'serviceDLLsha1sum': list(),
                        'serviceDLLsha256sum': list(),
                    }

                    if info['path'] and self._scan_executable_signature:
                        info.update(self._get_service_executable_hash(info['path']))

                    if self._scan_dlls and self._is_service_shared(info['path']) and info['pid']:
                        for dll_info in self._get_dll_info(info['pid']):
                            for k, v in dll_info.items():
                                if k not in info:
                                    info[k] = list()
                                info[k].append(v)

                    self._service_cache[service_name] = info
                except Exception as e:
                    logger.error(f'An error occurred while processing service {service_name}: {str(e)}')
                    continue
        except Exception as e:
            logger.error(f'Error enumerating services: {str(e)}')
        finally:
            win32service.CloseServiceHandle(scm)

    def _get_service_args(self, binpath: str) -> str | None:
        parts = binpath.split(' ')
        if len(parts) < 2:
            return None
        return ' '.join(parts[1:])

    def _get_service_status(self, status_code: int) -> str:
        return {
            win32service.SERVICE_STOPPED: 'Stopped',
            win32service.SERVICE_START_PENDING: 'Start Pending',
            win32service.SERVICE_STOP_PENDING: 'Stop Pending',
            win32service.SERVICE_RUNNING: 'Running',
            win32service.SERVICE_CONTINUE_PENDING: 'Continue Pending',
            win32service.SERVICE_PAUSE_PENDING: 'Pause Pending',
            win32service.SERVICE_PAUSED: 'Paused'
        }.get(status_code, 'Unknown')

    def _get_service_start_type(self, start_type: int) -> str:
        return {
            win32service.SERVICE_AUTO_START: 'Auto',
            win32service.SERVICE_BOOT_START: 'Boot',
            win32service.SERVICE_DEMAND_START: 'Demand',
            win32service.SERVICE_DISABLED: 'Disabled',
            win32service.SERVICE_SYSTEM_START: 'System'
        }.get(start_type, 'Unknown')

    def _is_service_shared(self, srvc_binpath: str) -> bool:
        system_root = os.getenv('SystemRoot')
        svchost_path = os.path.join(system_root, 'system32', 'svchost.exe')
        return srvc_binpath.lower().startswith(svchost_path.lower())

    def _get_service_executable_hash(self, binary_path: str) -> dict[str, str]:
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


    def _get_dll_info(self, pid: int) -> list[dict[str, str]]:
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
            modlist = win32process.EnumProcessModules(proc_handle)
        except Exception as e:
            logger.warning(f'Error during a call to EnumProcessModules for {pid=}: {str(e)}')
            return result

        try:
            for mod in modlist:
                modname = win32process.GetModuleFileNameEx(proc_handle, mod)
                if modname.endswith('.dll') and os.path.exists(modname):
                    dll_data = {
                        'serviceDLL': modname,
                        'serviceDLLmd5sum': calculate_hash(modname, hashlib.md5),
                        'serviceDLLsha1sum': calculate_hash(modname, hashlib.sha1),
                        'serviceDLLsha256sum': calculate_hash(modname, hashlib.sha256),
                    }

                    dll_data.update(self._get_dll_signature_info(modname))

                    result.append(dll_data)
        except Exception as e:
            logger.warning(f'Error during a call to GetModuleFileNameEx for module: {str(e)}')

        finally:
            win32api.CloseHandle(proc_handle)


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


    def _get_service_info(self) -> dict[str, dict]:
        if not self._service_cache:
            self._populate_cache()
        return self._service_cache


    def _update_scan_flags(self, items: list[IndicatorItem]) -> None:
        self._scan_executable_signature = any(i for i in items if 'sum' in i.term.lower())
        self._scan_dlls = any(i for i in items if 'dll' in i.term.lower())
def init(config: ConfigObject):
    return ServiceItemHandler(config)