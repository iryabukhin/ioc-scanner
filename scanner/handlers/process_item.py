import psutil
import socket
import hashlib
import os
from typing import List, Dict, Optional, Union, Callable

from loguru import logger

from scanner.config import ConfigObject
from scanner.core import BaseHandler, ConditionValidator
from scanner.models import IndicatorItem, IndicatorItemOperator
from scanner.utils import OSType
from scanner.utils.hash import calculate_hash


class ProcessItemHandler(BaseHandler):

    @staticmethod
    def get_supported_terms() -> List[str]:
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

    def validate(self, items: List[IndicatorItem], operator: IndicatorItemOperator) -> bool:
        valid_items = []
        for item in items:
            term = item.context.search
            value = self._get_value(term)
            if value is not None and ConditionValidator.validate_condition(item, value):
                valid_items.append(item)
        return bool(valid_items) if operator is IndicatorItemOperator.OR else len(valid_items) == len(items)

    def _get_value(self, term: str) -> Optional[Union[str, int]]:
        if not self._process_info:
            self._populate_process_info()
        return self._process_info.get(term)

    def _populate_process_info(self) -> None:
        self._process_info = {}

        def add_to_data(data, items):
            for item in items:
                for key, value in item.items():
                    key = f'ProcessItem/HandleList/Handle/{key}'
                    data.setdefault(key, []).append(value)

        for proc in psutil.process_iter():
            data = self._fetch_basic_process_data(proc)
            if OSType.is_linux():
                handles = list(self._get_process_handles(proc))
                sockets = list(self._get_process_sockets(proc))
                add_to_data(data, handles)
                add_to_data(data, sockets)

            self._process_info[str(proc.pid)] = data

    def _fetch_basic_process_data(self, proc) -> Dict:
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


def init(config: ConfigObject):
    return ProcessItemHandler(config)
