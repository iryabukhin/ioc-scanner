
from typing import List, Dict, Union, Optional
from .loader import ConfigLoader
from .config_object import ConfigObject

import os


class ConfigManager:

    def __init__(self):
        self._loaders: List[ConfigLoader] = list()

    def add_loader(self, loader: ConfigLoader, append: bool = True):
        if append:
            self._loaders.append(loader)
        else:
            self._loaders.insert(0, loader)


    def load_config(self) -> ConfigObject:
        config = ConfigObject()
        for loader in self._loaders:
            config.update(loader.load())
        return config

    def env_override(self, config: ConfigObject):
        for k, v in config.items():
            if isinstance(v,str) and k in os.environ:
                config[k] = os.environ[k]
        return config