
from scanner.config import ConfigManager, YamlConfigLoader
from scanner.core.scanner import IOCScanner
from scanner.utils import parse

FILEPATH = 'ioc/cisco/powelike.ioc.xml'

mngr = ConfigManager()
mngr.add_loader(YamlConfigLoader('config.yaml'))
config = mngr.load_config()

import winreg as wg
from scanner.handlers.registry_item import RegistryItemHandler

handler = RegistryItemHandler(config)

for value in handler._enumerate_path_values(wg.HKEY_LOCAL_MACHINE, 'HKEY_LOCAL_MACHINE', 'Software\Microsoft\Windows NT\CurrentVersion'):
    print(value)

exit(0)

with open(FILEPATH, 'r') as f:
    try:
        content = f.read()
        indicators = parse(content)


        # matched_iocs = IOCScanner(config).process(indicators)
        # print(f'{matched_iocs=}')
    except Exception as e:
        print(
            f'An error occurred: ' + str(e)
        )