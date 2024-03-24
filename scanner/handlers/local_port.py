
import os
import psutil
import socket

from datetime import datetime
from typing import List, Dict, Optional, Union
from scanner.core import BaseHandler
from scanner.models import IndicatorItem, IndicatorItemOperator

class LocalPortHandler(BaseHandler):
    def __init__(self):
        self._port_info = {}

    @staticmethod
    def get_supported_terms() -> List[str]:
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

    def validate(self, items: List[IndicatorItem], operator: IndicatorItemOperator) -> bool:
        valid_items = []
        for item in items:
            term = self._get_value_to_check(item)
            if not term:
                return False

            if self._evaluate_condition(term, item):
                valid_items.append(item)

        return bool(valid_items) if operator is IndicatorItemOperator.OR else len(valid_items) == len(items)

    def _get_value_to_check(self, item: IndicatorItem):
        try:
            return item.context.search.split('/')[1]
        except Exception as e:
            return None


    def _populate_port_info(self):
        connections = psutil.net_connections()
        for conn in connections:
            # skip sockets that are not UDP or TCP
            if conn.type not in [socket.SOCK_STREAM, socket.SOCK_DGRAM]:
                continue

            self._port_info[conn.laddr.port] = {
                'localIP': conn.laddr.ip,
                'remoteIP': conn.raddr.ip,
                'localPort': conn.laddr.port,
                'remotePort': conn.raddr.port,
                'protocol': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                'state': conn.status,
            }

            if conn.pid is None:
                continue

            proc = psutil.Process(conn.pid)

            self._port_info[conn.laddr.port]['pid'] = proc.pid
            self._port_info[conn.laddr.port]['path'] = proc.cmdline()
            self._port_info[conn.laddr.port]['CreationTime'] = datetime.fromtimestamp(proc.create_time())

    def _evaluate_condition(self, term: str, item: IndicatorItem):
        if not self._port_info:
            self._populate_port_info()

        value_to_check = item.content.content
        found = filter(
            lambda c: c.get(term) == value_to_check,
            self._port_info
        )
        found = len(found) > 0
        return not found if item.negate else found

def init():
    return (
        LocalPortHandler(),
        LocalPortHandler.get_supported_terms()
    )
