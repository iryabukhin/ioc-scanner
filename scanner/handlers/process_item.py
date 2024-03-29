import psutil
import socket
import hashlib
from typing import List, Dict, Optional, Union, Callable

from loguru import logger

from scanner.core import BaseHandler, ConditionValidator
from scanner.models import IndicatorItem, IndicatorItemOperator
from scanner.utils.hash import calculate_hash


def calculate_hash(file_path: str, hash_algorithm: Callable):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            return hash_algorithm(data).hexdigest()
    except Exception as e:
        logger.error(f'Error occurred while calculating hash for file {file_path}: {e}')
        return None


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
        for proc in psutil.process_iter():
            self._process_info[str(proc.pid)] = {
                **self._fetch_basic_process_data(proc),
            }

    def _fetch_basic_process_data(self, proc) -> Dict:
        return {
            'pid': proc.pid,
            'name': proc.name(),
            'Username': proc.username(),
            'arguments': ' '.join(proc.cmdline()[1:]) if len(proc.cmdline()) > 1 else '',
            'startTime': proc.create_time(),
            'path': proc.cmdline(),
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
                }
        except psutil.NoSuchProcess:
            print(f'No process found with PID {str(process.pid)}')
            return []
        except Exception as e:
            print(f'Error occurred while retrieving handles for process {str(process.pid)}: {str(e)}')
            return []

    def _get_process_sockets(self, process: psutil.Process):
        try:
            for c in process.connections():
                yield {
                    'SocketType': '',  # TODO: find out how to determine socket type on win/linux
                    'SocketProtocol': self._get_socket_type(c.type),
                    'SocketState': c.status,
                    'SocketLocalAddress': c.laddr.ip,
                    'SocketLocalPort': str(c.laddr.port),
                    'SocketRemoteAddress': c.raddr.ip,
                    'SocketRemotePort': str(c.raddr.port),
                }
        except Exception as e:
            logger.error(
                f'Error occurred while retrieving active sockets for process {str(process.pid): {str(e)}}'
            )
            raise e

    def _get_socket_type(self, kind) -> str:
        return {
            socket.SocketKind.SOCK_DGRAM: 'UDP',
            socket.SocketKind.SOCK_STREAM: 'TCP',
            socket.SocketKind.SOCK_RAW: 'RAW',
            socket.SocketKind.SOCK_RDM: 'RDM',
            socket.SocketKind.SOCK_SEQPACKET: 'SEQPACKET'
        }.get(kind, None)

def init():
    return ProcessItemHandler()