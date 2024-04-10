import argparse
import os
import scanner.config

from scanner.core.scanner import IOCScanner
from scanner.utils import parse

from loguru import logger

def load_configuration(config_path: str):
    config_manager = scanner.config.ConfigManager()
    if config_path.endswith(('.yaml', '.yml')):
        config_manager.add_loader(scanner.config.YamlConfigLoader(config_path))
    elif config_path.endswith('.json'):
        config_manager.add_loader(scanner.config.JsonConfigLoader(config_path))
    else:
        raise ValueError('Unsupported configuration file format. Please use JSON or YAML.')
    return config_manager.load_config()

def configure_logger(verbosity: int):
    if verbosity == 1:
        logger.remove()
        logger.add(lambda msg: print(msg, end=''), level='WARNING')
    elif verbosity == 2:
        logger.remove()
        logger.add(lambda msg: print(msg, end=''), level='INFO')
    elif verbosity == 3:
        logger.remove()
        logger.add(lambda msg: print(msg, end=''), level='DEBUG')
    else:
        logger.remove()
        logger.add(lambda msg: print(msg, end=''), level='ERROR')

def main():
    parser = argparse.ArgumentParser(description='Launch IOCScanner with specified options.')
    parser.add_argument('-c', '--config', required=True, help='Path to the configuration file (JSON or YAML).')
    parser.add_argument('-i', '--ioc', required=True, help='Path to an OpenIoC XML file or a directory containing these files.')
    parser.add_argument('-v', '--verbosity', type=int, choices=[1, 2, 3], help='Set the verbosity level: 1 for warnings, 2 for info, 3 for debug.')
    args = parser.parse_args()

    configure_logger(args.verbosity)

    try:
        config = load_configuration(args.config)
    except ValueError as e:
        logger.error(f'Error loading configuration: {e}')
        return

    if not os.path.exists(args.ioc):
        logger.error('The specified IOC file or directory does not exist.')
        return

    try:
        with open(args.ioc, 'r') as ioc_file:
            content = ioc_file.read()
            indicators = parse(content)
            matched_iocs = IOCScanner(config).process(indicators)
            if matched_iocs:
                logger.info('General result: Valid')
                valid_ids = [i.id for i in indicators if i.id in matched_iocs]
                logger.info('Valid indicators IDs: {}', ', ' . join(valid_ids))
            else:
                logger.warning('General result: Invalid')
    except Exception as e:
        logger.exception(f'An error occurred while processing the IOC file: {e}')

if __name__ == '__main__':
    main()