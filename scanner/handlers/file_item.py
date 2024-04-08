from typing import Union, Optional, List, Dict, ByteString
import os
import stat
import hashlib
import psutil

from datetime import datetime, timezone

from scanner.config import ConfigObject
from scanner.core import BaseHandler, ConditionValidator
from scanner.models import (
    IndicatorItem,
    IndicatorItemOperator as Operator,
    IndicatorItemCondition as Condition
)
from scanner.utils import OSType

if OSType.is_win():
    import pefile

from loguru import logger


HASH_CHUNK_SIZE = 4096


class FileItemHandler(BaseHandler):

    WIN_SYS_DRIVE = 'C:\\'
    LINUX_DEFAULT_ROOT_PATH = '/'

    # Predefined paths to skip on Linux platforms
    SKIP_PATHS_FULL = {
        '/proc', '/dev',
        '/sys/kernel/debug',
        '/sys/kernel/slab',
        '/sys/devices',
        '/usr/src/linux'
    }
    MOUNTED_DEVICES = {'/media', '/volumes'}
    SKIP_PATHS_END = {'/initctl'}

    MAX_FILE_SIZE_MB = 32

    def __init__(self, config: ConfigObject):
        super().__init__(config)

        self.file_cache = {}

        config = self.config.get('file_item', {})
        self._scan_all_drives = config.get('scan_all_drives', False)
        self._max_file_size = config.get('max_file_size_mb', self.MAX_FILE_SIZE_MB)

    @staticmethod
    def get_supported_terms() -> List[str]:
        return [
            'FileItem/Md5sum',
            'FileItem/Sha1sum',
            'FileItem/Sha256sum',
            'FileItem/FileName',
            'FileItem/FilePath',
            'FileItem/FullPath',
            'FileItem/FileExtension',
            'FileItem/SizeInBytes',
            'FileItem/Created',
            'FileItem/Modified',
            'FileItem/Accessed',
        ]

    def _build_file_info(self, full_path: str) -> Dict:
        result = {
            'FileName': os.path.basename(full_path),
            'FilePath': os.path.abspath(full_path),
            'FileExtension': os.path.splitext(full_path)[1],
            'SizeInBytes': os.path.getsize(full_path),
            'Created': self._get_creation_time(full_path),
            'Modified': datetime.fromtimestamp(os.path.getmtime(full_path), timezone.utc),
            'Accessed': datetime.fromtimestamp(os.path.getatime(full_path), timezone.utc),
        }

        hash_methods = [hashlib.md5(), hashlib.sha1(), hashlib.sha256()]
        hashes = {h.name: h for h in hash_methods}
        with open(full_path, 'rb') as f:
            for chunk in iter(lambda: f.read(HASH_CHUNK_SIZE), b""):
                for hash_obj in hashes.values():
                    hash_obj.update(chunk)
        result.update({f'{h.name.title()}sum': h.hexdigest() for h in hashes.values()})
        return result

    def validate(self, items: List[IndicatorItem], operator: Operator) -> bool:
        fullpath_item = next(
            (i for i in items if i.context.search == 'FileItem/FullPath'),
            None
        )
        if fullpath_item is not None and operator is Operator.AND:
            path = fullpath_item.content.content
            path = os.path.expandvars(path)
            if path not in self.file_cache:
                self._populate_cache(path)
        elif not self.file_cache:
            self._populate_cache()

        valid_items = list()
        for item in items:
            value_to_check = self.file_cache.get(item.get_term())
            if value_to_check is not None and ConditionValidator.validate_condition(item, value_to_check):
                valid_items.append(item)

        return bool(valid_items) if operator is Operator.OR else len(valid_items) == len(items)

    def _populate_cache(self, root: Optional[str] = None) -> None:
        if root is None:
            if OSType.is_win():
                if self._scan_all_drives:
                    for drive_base_path in self._get_all_drives():
                        self._populate_cache(drive_base_path)
                else:
                    root = self.WIN_SYS_DRIVE
            elif OSType.is_linux():
                root = self.LINUX_DEFAULT_ROOT_PATH

        self.file_cache = {
            i['FileItem/FilePath'] for i in self._recursive_scan(root)
        }

    def _recursive_scan(self, root: str) -> List[Dict]:
        logger.debug(f'Begin scanning root path "{root}" ...')
        if not os.path.exists(root):
            logger.warning(f'Path {root} does not exist, aborting scan...')
            return []

        for rootdir, dirs, files in os.walk(root, topdown=True, followlinks=False):
            dirs[:] = [d for d in dirs if not self._should_skip(os.path.join(rootdir, d))]

            for filename in files:
                fpath = os.path.join(rootdir, filename)
                if self._should_process_file(fpath):
                    try:
                        yield self._build_file_info(fpath)
                    except PermissionError as e:
                        logger.warning(f'Could not scan file "{fpath}" due to permission error: {str(e)}')
                    except Exception as e:
                        logger.warning(f'Could not scan file "{fpath}" due to an unknown error: {str(e)}')

    def _get_all_drives(self) -> List[str]:
        return [p.mountpoint for p in psutil.disk_partitions() if p.fstype == 'NTFS']

    def _get_creation_time(self, full_path) -> Optional[datetime]:
        try:
            if OSType.is_win():
                timestamp = os.path.getctime(full_path)
            else:
                stat_result = os.stat(full_path)
                timestamp = getattr(stat_result, 'st_birthtime', stat_result.st_mtime)
            return datetime.fromtimestamp(timestamp, tz=timezone.utc)
        except Exception as e:
            logger.error(f'Error getting creation time for {full_path}: {e}')
            return None

    def _should_skip(self, path: str) -> bool:
        lower_path = path.lower()
        return any(lower_path.startswith(skip.lower()) for skip in self.SKIP_PATHS_FULL)

    def _should_process_file(self, fpath: str) -> bool:
        fstat = os.stat(fpath)
        fmode = fstat.st_mode
        if (stat.S_ISCHR(fmode) or stat.S_ISBLK(fmode) or stat.S_ISFIFO(fmode) or stat.S_ISLNK(fmode) or stat.S_ISSOCK(fmode)):
            return False
        if fstat.st_size > self._max_file_size * 1024 * 1024:
            logger.info(f'Skipping file "{fpath}" because its size exceeds {self._max_file_size} MB')
            return False
        return True

    def _build_pe_info(self, full_path: str) -> Dict:
        try:

            logger.debug(f'Begin processing PE info for file "{full_path}" ...')
            try:
                exe = pefile.PE(full_path)
            except pefile.PEFormatError as e:
                logger.warning(f'Could not process PE file "{full_path}" due to PE format error: {str(e)}')
                return {}

            info = {
                'BaseAddress': hex(exe.OPTIONAL_HEADER.ImageBase),
                'PETimeStamp': datetime.utcfromtimestamp(exe.FILE_HEADER.TimeDateStamp),
                'Subsystem': exe.OPTIONAL_HEADER.Subsystem,
                'NumberOfSections': exe.FILE_HEADER.NumberOfSections,
                'Sections': [{
                    'Name': section.Name.decode().rstrip('\x00'),
                    'SizeInBytes': section.SizeOfRawData
                } for section in exe.sections
                ],
                # Additional fields to be added here
            }

            # Example for handling digital signatures (simplified, real-world usage might require more detailed checks)
            if hasattr(exe, 'DIRECTORY_ENTRY_SECURITY'):
                info['DigitalSignature'] = {'SignatureExists': True}
                # Further processing required to verify signature and extract certificate details
            else:
                info['DigitalSignature'] = {'SignatureExists': False}

            # Example for handling exports
            if hasattr(exe, 'DIRECTORY_ENTRY_EXPORT'):
                exports = exe.DIRECTORY_ENTRY_EXPORT
                info['Exports'] = {
                    'DllName': exports.name.decode(),
                    'NumberOfFunctions': exports.struct.NumberOfFunctions,
                    'NumberOfNames': exports.struct.NumberOfNames,
                    # Additional fields to be added here
                }

            # Additional PE information extraction logic goes here

            return info
        except Exception as e:
            logger.error(f'Error processing PE file {full_path}: {e}')
            return {}


def init(config: ConfigObject):
    return FileItemHandler(config)
