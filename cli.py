import argparse
import os
import sys
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
    level = {
        0: 'ERROR',
        1: 'WARNING',
        2: 'INFO',
        3: 'DEBUG',
    }.get(verbosity, 'DEBUG')
    logger.remove()
    logger.add(sys.stdout, level=level, colorize=True)

def iocscan(args):

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
                logger.info('Valid indicators IDs: {}', ', '.join(valid_ids))
            else:
                logger.warning('General result: Invalid')
    except Exception as e:
        logger.exception(f'An error occurred while processing the IOC file: {e}')


def main():
    parser = argparse.ArgumentParser(description='Launch a scanner in on the specified modes')

    common_args_parser = argparse.ArgumentParser(add_help=False)
    common_args_parser.add_argument(
        '-v', '--verbose', dest='verbosity', action='count', default=1,
        help='Set the verbosity level: 1 for warnings, 2 for info, 3 for debug.'
    )

    subparsers = parser.add_subparsers(dest='mode', required=True, help='mode of operation of scanner')

    subparser = subparsers.add_parser('iocscan', help='perform a scan of an OpenIOC document', parents=[common_args_parser])
    subparser.add_argument('-i', '--ioc', required=True, help='Path to an OpenIoC XML file or a directory containing these files.')
    subparser.add_argument('-c', '--config', required=True, help='Path to the configuration file (JSON or YAML).')

    subparser = subparsers.add_parser('yara-mem', help='Yara scan of process memory', parents=[common_args_parser])
    group = subparser.add_mutually_exclusive_group(required=True)
    group.add_argument('-p', '--pid', required=False, help='Process ID to scan')
    group.add_argument('-n', '--name', required=False, help='Process name to scan')

    subparser = subparsers.add_parser('yara-file', help='Yara scan of a file', parents=[common_args_parser])
    subparser.add_argument('-f', '--file', required=True, help='Path to a file to scan')

    args = parser.parse_args()

    configure_logger(args.verbosity)

    match args.mode:
        case 'iocscan':
            iocscan(args)
        case 'yara-mem':
            pass  # TODO: Implement yara-mem processing
        case 'yara-file':
            pass  # TODO: Implement yara-file processing
        case _:
            logger.error(f'Unsupported mode: {args.mode}')


if __name__ == '__main__':
    main()