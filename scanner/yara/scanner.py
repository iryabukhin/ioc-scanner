import io
import json
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
        self._ignore_compilation_errors: bool = False

    @property
    def rules(self) -> yara.Rules:
        if self._rules is None:
            raise ValueError(
                'No rules loaded yet! Compile or load rules first!'
            )
        return self._rules

    def compile_rules(self, rules_source: str, source_type: SourceType, vars: Optional[dict] = None):
        all_rules = None
        vars = {} if vars is None else vars
        if source_type == SourceType.FILE:
            path = rules_source
            if not os.path.exists(path):
                raise FileNotFoundError(f'YARA rule file {path} does not exist!')
            path = os.path.abspath(path)
            rule_files = [f for f in os.listdir(path)] if os.path.isdir(path) else [path]
            for filename in rule_files:
                if os.path.isdir(filename):
                    continue
                extension = os.path.splitext(filename)[1].lower()
                if extension != '.yar' and extension != '.yara':
                    continue
                with open(filename, 'r') as f:
                    file_content = f.read()
                    try:
                        compiled_rule = yara.compile(source=file_content, externals=vars)
                    except yara.Error as e:
                        if self._ignore_compilation_errors:
                            continue
                        else:
                            raise ValueError(f'Could not compile rule from file {filename}: {str(e)}')
                    all_rules += file_content
            self._rules = yara.compile(source=all_rules, externals=vars)
        elif source_type == SourceType.STRING:
            self._rules = yara.compile(source=rules_source, externals=vars)
        else:
            raise ValueError("source_type must be either SourceType.FILE or SourceType.STRING")
        return self._rules


    def load_compiled_rules(self, data: bytes) -> None:
        buffer = io.BytesIO()
        buffer.write(data)
        buffer.seek(0)
        self._rules = yara.load(file=buffer)

    def scan_file(self, file_path: str, rule_variables: Optional[dict[str]] = None) -> list[dict[str, list[str]]]:
        if not os.path.exists(file_path):
            raise ValueError(f'File does not exist: {file_path}')

        full_path = os.path.abspath(file_path)
        return self._do_scan({
            'filepath': full_path,
            'externals': rule_variables
        })

    def scan_process(self, pid: int, vars: Optional[dict] = None) -> list[dict[str, list[str]]]:
        if vars is None:
            vars = {}

        try:
            proc_data = psutil.Process(pid=pid).memory_maps()
        except psutil.AccessDenied as e:
            raise PermissionError(f'Cannot scan process {pid} due to a permission error')
        except psutil.NoSuchProcess as e:
            raise ValueError(f'No such process with {pid=}')

        return self._do_scan({'pid': pid, 'externals': vars})

    def _do_scan(self, params):
        matches = self._rules.match(
            **params,
            timeout=self._timeout
        )
        return [self._process_match(m) for m in matches]

    def _process_match(self, match: yara.Match) -> dict[str, list[str]]:
        result = {}
        matched_strings = {}
        if hasattr(match, 'strings'):
            for string in match.strings:
                string_value = str(string.instances[0]).replace("'", '\\')
                if len(string_value) > self.MAX_MATCH_DISPLAY_LEN:
                    string_value = string_value[:self.MAX_MATCH_DISPLAY_LEN] + " ... (truncated)"
                matched_strings[string.identifier] = string_value
        result[match.rule] = matched_strings
        return result

