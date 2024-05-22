import argparse
import csv
import json
import os
import sys
from typing import io

import psutil

from scanner.core import IOCScanner
from scanner.config import ConfigManager, YamlConfigLoader, JsonConfigLoader
from scanner.yara import YaraScanner, SourceType
from scanner.utils import OpenIOCXMLParser


from loguru import logger

def load_configuration(config_path: str):
    config_manager = ConfigManager()
    if config_path.endswith(('.yaml', '.yml')):
        config_manager.add_loader(YamlConfigLoader(config_path))
    elif config_path.endswith('.json'):
        config_manager.add_loader(JsonConfigLoader(config_path))
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


def yara_scan(args):

    rules_file_path = args.rules_file

    try:
        scanner = YaraScanner()
        scanner.compile_rules(rules_file_path, SourceType.FILE)
    except Exception as e:
        print(f'Could not compile rules due to an error: {str(e)}')
        sys.exit(1)

    try:
        if args.pid:
            matches = scanner.scan_process(args.pid)
        elif args.process_name:
            procs = [p for p in psutil.process_iter(['name', 'pid']) if p.name() == args.process_name]
            if not procs:
                print(f'Could not find any process with the name "{args.process_name}"!')
                sys.exit(0)
            matches = []
            for proc in procs:
                matches.extend(scanner.scan_process(proc.pid))
        else:
            matches = scanner.scan_file(args.filepath)
    except Exception as e:
        print(f'An error occurred during the scan: {str(e)}')
        sys.exit(1)

    if args.format == 'json':
        output = json.dumps(matches)
        print(output)
    elif args.format == 'csv':
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Rule Name", "Match Index", "Matched String"])
        for match in matches:
            for rule_name, strings in match.items():
                for i, string in enumerate(strings):
                    writer.writerow([rule_name, i + 1, string])
        print(output.getvalue())
    else:
        print('Found matches: ')
        for match in matches:
            for rule_name, strings in match.items():
                print(f'Rule: {rule_name}')
                for i, string in enumerate(strings):
                    print(f'\t {str(i+1)}: {string}')


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
            parser = OpenIOCXMLParser()
            indicators = parser.parse(content)
            if not indicators:
                logger.error('Unable to parse OpenIoC document content.')
                return
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
    common_args_parser.add_argument(
        '-c', '--config',
        required=True,
        help='Path to the configuration file (JSON or YAML).'
    )
    common_args_parser.add_argument(
        '--format',
        choices=['json', 'csv', 'plain'],
        default='json',
        help='Specify the output format (JSON, CSV, or plain).'
    )

    subparsers = parser.add_subparsers(dest='mode', required=True, help='mode of operation of scanner')

    subparser = subparsers.add_parser(
        'iocscan',
        help='perform a scan of an OpenIOC document',
        parents=[common_args_parser]
    )
    subparser.add_argument(
        '-i', '--ioc',
        required=True,
        help='Path to an OpenIoC XML file or a directory containing these files'
    )

    subparser = subparsers.add_parser('yara', help='Yara scan of a file or process memory', parents=[common_args_parser])

    subparser.add_argument(
        '-r', '--rules-file',
        required=True,
        help='Path to a file or directory containing Yara rules '
    )

    group = subparser.add_mutually_exclusive_group(required=True)
    group.add_argument('-p', '--pid', required=False, help='Process ID to scan')
    group.add_argument('-n', '--process-name', required=False, help='Process name to scan')
    group.add_argument('-f', '--filepath', required=False, help='Path to a file to scan')

    args = parser.parse_args()

    configure_logger(args.verbosity)

    match args.mode:
        case 'iocscan':
            iocscan(args)
        case 'yara':
            yara_scan(args)
        case _:
            print(f'Unsupported mode: {args.mode}!')
            print(f'')
            sys.exit(1)


if __name__ == '__main__':
    main()
