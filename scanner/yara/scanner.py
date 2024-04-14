import yara
import os
import sqlite3
import sys
from enum import Enum, auto

from loguru import logger


class SourceType(Enum):
    FILE = auto()
    STRING = auto()


class YaraScanner:
    def __init__(self, rules_source: str, source_type: SourceType = SourceType.FILE):
        self.rules = self.compile_rules(rules_source, source_type)

    def compile_rules(self, rules_source: str, source_type: SourceType):
        try:
            if source_type == SourceType.FILE:
                return yara.compile(filepath=rules_source)
            elif source_type == SourceType.STRING:
                return yara.compile(source=rules_source)
            else:
                raise ValueError("source_type must be either SourceType.FILE or SourceType.STRING")
        except yara.SyntaxError as e:
            logger.error(f'Syntax error in YARA rules: {e}')
            sys.exit(1)
        except yara.Error as e:
            logger.error(f'General YARA error: {e}')
            sys.exit(1)
        except Exception as e:
            logger.error(f'Unexpected error compiling YARA rules: {e}')
            sys.exit(1)

    def file_scan(self, file_path: str):
        if not os.path.exists(file_path):
            logger.error(f'File does not exist: {file_path}')
            return None

        try:
            matches = self.rules.match(file_path)
            if matches:
                logger.info(f'YARA matches found in {file_path}: {matches}')
            else:
                logger.info(f'No YARA matches found in {file_path}.')
            return matches
        except yara.Error as e:
            logger.error(f'Error scanning file with YARA: {e}')
            return None

    def process_scan(self, pid: int):
        try:
            matches = self.rules.match(pid=pid)
            if matches:
                logger.info(f'YARA matches found in process {pid}: {matches}')
            else:
                logger.info(f'No YARA matches found in process {pid}.')
            return matches
        except yara.Error as e:
            logger.error(f'Error scanning process with YARA: {e}')
            return None