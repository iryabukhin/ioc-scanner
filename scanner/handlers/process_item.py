import psutil
import socket
import hashlib
import os

from loguru import logger

from scanner.config import ConfigObject
from scanner.core import BaseHandler, ConditionValidator
from scanner.models import IndicatorItem, IndicatorItemOperator as Operator, ValidationResult
from scanner.utils import OSType
from scanner.utils.hash import calculate_hash


class ProcessItemHandler(BaseHandler):

    def __init__(self, config: ConfigObject):
        super().__init__(config)

        self._lazy_evaluation = config.get('lazy_evaluation', False)
        config = config.get('process_item', {})

        self._parse_handles = config.get('parse_handles', False)
        self._parse_sockets = config.get('parse_sockets', False)
        self._ignore_permission_errors = config.get('ignore_permission_errors', True)

        self._process_info = None

    @staticmethod
    def get_supported_terms() -> list[str]:
        return [
            'ProcessItem/arguments',
            'ProcessItem/name',
            'ProcessItem/parentpid',
            'ProcessItem/path',
            'ProcessItem/pid',
            'ProcessItem/startTime',
            'ProcessItem/Username',
            'ProcessItem/HandleList/Handle/SocketType',
            'ProcessItem/HandleList/Handle/SocketProtocol',
            'ProcessItem/HandleList/Handle/SocketState',
            'ProcessItem/HandleList/Handle/SocketLocalAddress',
            'ProcessItem/HandleList/Handle/SocketLocalPort',
            'ProcessItem/HandleList/Handle/SocketRemoteAddress',
            'ProcessItem/HandleList/Handle/SocketRemotePort',
            'ProcessItem/HandleList/Handle/Md5sum',
            'ProcessItem/HandleList/Handle/Sha1sum',
            'ProcessItem/HandleList/Handle/Sha256sum',
        ]

    def validate(self, items: list[IndicatorItem], operator: Operator) -> bool | ValidationResult:
        valid_items = set()
        for pid, process_data in self._get_process_info().items():
            for item in items:
                value = process_data.get(item.term)
                if value is not None and ConditionValidator.validate_condition(item, value):
                    valid_items.add(item)
                    if operator == Operator.OR and self._lazy_evaluation:
                        return True
        return bool(valid_items) if operator == Operator.OR else len(valid_items) == len(items)

    def _get_process_info(self) -> dict[str, dict]:
        if not self._process_info:
            self._populate_process_info()
        return self._process_info

    def _populate_process_info(self) -> None:
        self._process_info = {}

        def add_to_data(data, path, items):
            for item in items:
                for key, value in item.items():
                    key = f'ProcessItem/{path}/{key}'
                    data.setdefault(key, []).append(value)

        for proc in psutil.process_iter():
            if self._should_skip_process(proc):
                continue
            try:
                data = self._fetch_basic_process_data(proc)
                if OSType.is_linux():
                    if self._parse_handles:
                        add_to_data(data, 'HandleList/Handle', list(self._get_process_handles(proc)))
                    if self._parse_sockets:
                        add_to_data(data, 'HandleList/Handle', list(self._get_process_sockets(proc)))
                self._process_info[str(proc.pid)] = data
            except (PermissionError, psutil.AccessDenied) as e:
                logger.error(f'Error occurred while retrieving process info for process: {str(e)}')
                if self._ignore_permission_errors:
                    continue
                else:
                    raise e

    def _fetch_basic_process_data(self, proc) -> dict:
        return {
            'pid': proc.pid,
            'name': proc.name(),
            'Username': proc.username(),
            'arguments': ' '.join(proc.cmdline()[1:]) if len(proc.cmdline()) > 1 else '',
            'startTime': proc.create_time(),
            'path': proc.exe(),
            'parentpid': proc.ppid()
        }

    def _get_process_handles(self, process: psutil.Process):
        try:
            for file in process.open_files():
                yield {
                    'Md5sum': calculate_hash(file.path, hashlib.md5),
                    'Sha1sum': calculate_hash(file.path, hashlib.sha1),
                    'Sha256sum': calculate_hash(file.path, hashlib.sha256),
                    'User': process.username(),
                    'FileDescriptor': file.fd,
                    'Size': os.path.getsize(file.path),
                }
        except psutil.NoSuchProcess:
            logger.error(f'No process found with PID {str(process.pid)}')
        except Exception as e:
            logger.error(f'Error occurred while retrieving handles for process {str(process.pid)}: {str(e)}')

    def _get_process_sockets(self, process: psutil.Process):
        try:
            for c in process.connections():
                yield {
                    'SocketType': self._get_socket_type(c.type),
                    'SocketProtocol': self._get_socket_type(c.type),
                    'SocketState': c.status,
                    'SocketLocalAddress': c.laddr.ip if c.laddr else '',
                    'SocketLocalPort': str(c.laddr.port) if c.laddr else '',
                    'SocketRemoteAddress': c.raddr.ip if c.raddr else '',
                    'SocketRemotePort': str(c.raddr.port) if c.raddr else '',
                }
        except Exception as e:
            logger.error(f'Error occurred while retrieving active sockets for process {str(process.pid)}: {str(e)}')
            raise e

    def _get_socket_type(self, kind) -> str:
        return {
            socket.SocketKind.SOCK_DGRAM: 'UDP',
            socket.SocketKind.SOCK_STREAM: 'TCP',
            socket.SocketKind.SOCK_RAW: 'RAW',
            socket.SocketKind.SOCK_RDM: 'RDM',
            socket.SocketKind.SOCK_SEQPACKET: 'SEQPACKET'
        }.get(kind, 'Unknown')  # Default to 'Unknown' if kind is not found

    def _should_skip_process(self, proc) -> bool:
        return proc.pid == os.getpid() or proc.pid == 0


def init(config: ConfigObject):
    return ProcessItemHandler(config)
