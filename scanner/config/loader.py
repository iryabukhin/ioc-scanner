
from typing import Any, Tuple, Union, Optional, Iterable
import json
import yaml
import configparser
import os
import abc


class ConfigLoader:
    @abc.abstractmethod
    def load(self) -> dict[str, Any]:
        raise NotImplementedError

class FileConfigLoader(ConfigLoader):
    def __init__(self, file_path: str):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f'Configuration file {file_path} does not exist!')
        self.file_path = file_path

class JsonConfigLoader(FileConfigLoader):

    def load(self) -> dict[str, Any]:
        with open(self.file_path, 'r') as f:
            return json.load(f)

class YamlConfigLoader(FileConfigLoader):

    def load(self) -> dict[str, Any]:
        with open(self.file_path, 'r') as f:
            return yaml.safe_load(f)


class IniFileConfigLoader(FileConfigLoader):

    def load(self) -> dict[str, Any]:
        parser = configparser.ConfigParser()
        parser.read(self.file_path)
        # Convert to a dict of dicts
        return {section: dict(parser.items(section)) for section in parser.sections()}