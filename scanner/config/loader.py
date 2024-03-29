
from typing import Any, Dict, List, Tuple, Union, Optional, Iterable
import json
import yaml
import abc


class ConfigLoader:
    @abc.abstractmethod
    def load(self) -> Dict[str, Any]:
        raise NotImplementedError

class JsonConfigLoader(ConfigLoader):

    def __init__(self, file_path: str):
        self.file_path = file_path

    def load(self) -> Dict[str, Any]:
        with open(self.file_path, 'r') as f:
            return json.load(f)

class YamlConfigLoader(ConfigLoader):

    def __init__(self, file_path: str):
        self.file_path = file_path

    def load(self) -> Dict[str, Any]:
        with open(self.file_path, 'r') as f:
            return yaml.safe_load(f)

