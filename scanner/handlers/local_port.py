
import os
import psutil
import socket

from datetime import datetime

from scanner.config import ConfigObject
from scanner.core import BaseHandler, ConditionValidator
from scanner.models import IndicatorItem, IndicatorItemOperator as Operator, ValidationResult


class LocalPortHandler(BaseHandler):
    def __init__(self, config: ConfigObject):
        super().__init__(config)

        self._port_info = {}
        self._process_cache = {}

    @staticmethod
    def get_supported_terms() -> list[str]:
        return [
            'PortItem/CreationTime',
            'PortItem/localIP',
            'PortItem/localPort',
            'PortItem/path',
            'PortItem/pid',
            'PortItem/process',
            'PortItem/protocol',
            'PortItem/remoteIP',
            'PortItem/remotePort',
            'PortItem/state'
        ]

    def validate(self, items: list[IndicatorItem], operator: Operator) -> ValidationResult:
        result = ValidationResult()
        result.set_lazy_evaluation(self._lazy_evaluation)

        for item in items:
            if not self._port_info:
                self._populate_port_info()

            for port_data in self._port_info.values():
                value_to_check = port_data.get(item.term)
                if value_to_check is not None and ConditionValidator.validate_condition(item, value_to_check):
                    result.add_matched_item(item, context={'port_data': port_data})
                    if operator == Operator.OR and self._lazy_evaluation:
                        result.skip_remaining_items(items)
                        return result

        return result

    def _populate_port_info(self):
        connections = psutil.net_connections()
        for conn in connections:
            if conn.type not in [socket.SOCK_STREAM, socket.SOCK_DGRAM]:
                continue

            protocol = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
            key = (conn.laddr.ip, conn.laddr.port, protocol)
            self._port_info[key] = {
                'localIP': conn.laddr.ip,
                'remoteIP': conn.raddr.ip if conn.raddr else '',
                'localPort': conn.laddr.port,
                'remotePort': conn.raddr.port if conn.raddr else 0,
                'protocol': protocol,
                'state': conn.status,
            }

            if conn.pid and conn.pid not in self._port_info:
                try:
                    proc = psutil.Process(conn.pid)
                    self._process_cache[conn.pid] = {
                        'pid': proc.pid,
                        'path': proc.exe(),
                        'CreationTime': datetime.fromtimestamp(proc.create_time())
                    }
                except psutil.NoSuchProcess:
                    continue
            self._port_info[key].update(self._process_cache[conn.pid])

    def _evaluate_condition(self, term: str, item: IndicatorItem):
        if not self._port_info:
            self._populate_port_info()

        value_to_check = item.content.content
        found = any(c.get(term) == value_to_check for c in self._port_info.values())
        return not found if item.negate else found

def init(config: ConfigObject):
    return LocalPortHandler(config)
