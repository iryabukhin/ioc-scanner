from typing import Dict, List, Tuple, Union, Optional, Iterable, Any

class ConfigObject(dict):

    def __init__(self, *args, **kwargs):
        super(ConfigObject, self).__init__(*args, **kwargs)

        for arg in [*args, kwargs]:
            if isinstance(arg, dict):
                for k, v in arg.items():
                    self[k] = v
                    if isinstance(v, dict):
                        self[k] = ConfigObject(v)
                    elif isinstance(v, str) or isinstance(v, bytes):
                        self[k] = v
                    elif isinstance(v, Iterable):
                        klass = type(v)
                        map_value: list[Any] = []
                        for e in v:
                            map_e = ConfigObject(e) if isinstance(e, dict) else e
                            map_value.append(map_e)
                        self[k] = klass(map_value)

    def __getattr__(self, attr):
        return self.get(attr)

    def __setattr__(self, key, value):
        self.__setitem__(key, value)

    def __setitem__(self, key, value):
        super(ConfigObject, self).__setitem__(key, value)
        self.__dict__.update({key: value})

    def __delattr__(self, item):
        self.__delitem__(item)

    def __delitem__(self, key):
        super(ConfigObject, self).__delitem__(key)
        del self.__dict__[key]

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, d):
        self.__dict__.update(d)