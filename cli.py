import argparse
import csv
import json
import logging.handlers
import os
import socket
import sys
import io

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

def configure_logger(args):
    level = {
        0: 'ERROR',
        1: 'WARNING',
        2: 'INFO',
        3: 'DEBUG',
    }.get(args.verbosity, 'DEBUG')
    logger.remove()
    if args.syslog_server:
        try:
            host, port = args.syslog_server.split(':', 2)
            handler = logging.handlers.SysLogHandler(
                address=(host, port),
                socktype=socket.SOCK_STREAM
            )
            logger.add(handler)
        except Exception as e:
            pass
    else:
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


def print_recursive_dict(d: dict, prefix: str):
    for k, v in d.items():
        if isinstance(v, dict):
            print(f'{prefix}{k}:')
            print_recursive_dict(v, prefix + '  ')
        else:
            print(f'{prefix}{k}: {v}')

def print_indicator_matches(matches: list[dict], indent=0):
    prefix = '    ' * indent
    for match in matches:

        print(f'{prefix}Indicator ID: {match["id"]}')
        print(f'{prefix}Operator: {str(match["operator"])}')
        print(f'{prefix}Skipped items: {match["skipped_items"]}')

        if len(match['valid_items']) > 0:
            print(f'{prefix}Valid items: ')
            for item in match['valid_items']:
                print(f'{prefix*2}Item ID: {item["id"]}')
                print(f'{prefix*2}Item type: {item["type"]}')
                if item.get('match_details') is not None and len(item.get('match_details')) > 0:
                    print(f'{prefix*2}Match details: ')
                    print_recursive_dict(item['match_details'], prefix*2)

        if match.get('child_results') and len(match['child_results']) > 0:
            print_indicator_matches(match['child_results'], indent + 1)


def iocscan(args):

    try:
        config = load_configuration(args.config)
    except ValueError as e:
        print(f'Unable to load scanner configuration: {e}')
        sys.exit(1)

    if not os.path.exists(args.ioc):
        print('The specified IOC file or directory does not exist!')
        sys.exit(1)
    try:
        with open(args.ioc, 'r') as ioc_file:
            content = ioc_file.read()
            parser = OpenIOCXMLParser()
            indicators = parser.parse(content)
            if not indicators:
                logger.error('Unable to parse OpenIoC document content.')
                return

            scan_result = IOCScanner(config).process(indicators)

    except Exception as e:
        logger.exception(e)
        errmsg = f'An error occurred while processing the IOC file: {e}'
        print(errmsg)
        sys.exit(1)

    if args.format == 'json':
        output = scan_result.to_json(indent=4)
        print(output)
    elif args.format == 'plain':
        print(f'General result: {scan_result.result}')
        print(f'Scan duration: {str(scan_result.scan_duration)}')
        if len(scan_result.matches) > 0:
            print('Found matches: ')
            print_indicator_matches(scan_result.matches, indent=1)


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
        default='plain',
        help='Specify the output format (JSON, CSV, or plain).'
    )
    common_args_parser.add_argument(
        '--syslog-server',
        required=False,
        help='Specify the address and port of a remote syslog server (e.g. "127.0.0.1:13337"'
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
            sys.exit(1)


if __name__ == '__main__':
    main()
