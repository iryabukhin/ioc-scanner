from typing import Optional

import yara
import os
import psutil
import sys
from enum import Enum, auto

from loguru import logger


class SourceType(Enum):
    FILE = auto()
    STRING = auto()


class YaraScanner:

    MAX_MATCH_DISPLAY_LEN = 150

    DEFAULT_TIMEOUT_SEC = 10

    def __init__(self):
        self._rules: yara.Rules = None
        self._timeout = self.DEFAULT_TIMEOUT_SEC

    @property
    def rules(self) -> yara.Rules:
        return self._rules

    def compile_rules(self, rules_source: str, source_type: SourceType, vars: Optional[dict] = None):
        all_rules = None
        try:
            if source_type == SourceType.FILE:
                path = rules_source
                rule_files = [f for f in os.listdir(path)] if os.path.isdir(path) else path
                for filename in rule_files:
                    # nuh-uh, no recursion
                    if os.path.isdir(filename):
                        continue
                    extension = os.path.splitext(filename)[1].lower()
                    if extension != '.yar' and extension != '.yara':
                        continue
                    with open(filename, 'r') as f:
                        all_rules += yara.compile(source=f.read())
                return yara.compile(source=all_rules)
            elif source_type == SourceType.STRING:
                return yara.compile(source=rules_source)
            else:
                raise ValueError("source_type must be either SourceType.FILE or SourceType.STRING")
        except yara.SyntaxError as e:
            logger.error(f'Syntax error in YARA rules: {e}')
        except yara.Error as e:
            logger.error(f'General YARA error: {e}')
        except Exception as e:
            logger.error(f'Unexpected error compiling YARA rules: {e}')

    def scan_file(self, file_path: str, rule_variables: Optional[dict[str]] = None):
        if not os.path.exists(file_path):
            raise ValueError(f'File does not exist: {file_path}')

        return self._do_scan({
            'filepath': file_path,
            'externals': rule_variables
        })

    def scan_process(self, pid: int, vars: Optional[dict] = None):
        if vars is None:
            vars = {}
        try:
            proc_data = psutil.Process(pid=pid).memory_info()
        except Exception as e:
            raise PermissionError(
                f'Cannot scan process {pid} due to a permission error'
            )

        return self._do_scan({'pid': pid, 'externals': vars})

    def _do_scan(self, params):
        matches = self._rules.match(
            **params,
            timeout=self._timeout
        )
        return [self._process_match(m) for m in matches]

    def _process_match(self, match: yara.Match) -> tuple:
        matched_strings = []
        if hasattr(match, 'strings'):
            for string in match.strings:
                string_value = str(string.instances[0]).replace("'", '\\')
                if len(string_value) > self.MAX_MATCH_DISPLAY_LEN:
                    string_value = string_value[:self.MAX_MATCH_DISPLAY_LEN] + " ... (truncated)"
                matched_strings.append(
                    "{0}: '{1}'".format(string.identifier, string_value)
                )
        return match.rule, matched_strings

