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

from loguru import logger

if OSType.is_win():
    try:
        import win32file
        import win32api
    except Exception as e:
        logger.error(f'Could not import win32api or win32file: {str(e)}')



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
        self.config = config
        self.file_cache = {}

        self._scan_all_drives = config.file_item.scan_all_drives or False
        self._max_file_size = config.file_item.max_file_size_mb or self.MAX_FILE_SIZE_MB

    @staticmethod
    def get_supported_terms() -> List[str]:
        return [
'FileItem/Md5sum',
'FileItem/Sha1sum',
'FileItem/Sha256sum',
'FileItem/FileName',
'FileItem/FilePath',
'FileItem/FullPath'
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
        with open(full_path, 'rb') as f:
            for chunk in iter(lambda: f.read(HASH_CHUNK_SIZE), b""):
                for hash_obj in hash_methods:
                    hash_obj.update(chunk)
        result.update({f'{h.name.title()}sum': hash_obj.hexdigest() for h in hash_methods})
        return result

    def validate(self, items: List[IndicatorItem], operator: Operator) -> bool:
        fullpath_item = next(
            (i for i in items if i.context.search == 'FileItem/FullPath'),
            None
        )
        # if FullPath item is present and operator is AND, we can scan only the file specified in the FullPath item
        if fullpath_item is not None and operator is Operator.AND:
            path = fullpath_item.content.content
            if path not in self.file_cache:
                self._populate_cache(path)
        elif not self.file_cache:
            self._populate_cache()

        valid_items = list()
        # TODO: Implement better validation logic here
        for item in items:
            term = item.context.search
            value = self.file_cache.get(term)
            if value is not None and ConditionValidator.validate_condition(item, value):
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

    def _recursive_scan(self, root: Optional[str] = None) -> List[Dict]:
        if root is None:
            if OSType.is_win():
                if self._scan_all_drives:
                    for drive_base_path in self._get_all_drives():
                        self._recursive_scan(drive_base_path)
                else:
                    root = self.WIN_SYS_DRIVE
            elif OSType.is_linux():
                root = self.LINUX_DEFAULT_ROOT_PATH

        logger.info(f'Begin scanning root path "{root}" ...')
        if not os.path.exists(root):
            logger.info(f'Path {root} does not exist, aborting scan...')
            return []

        # TODO: add processing of user-specific environment variables (i.e. %USERPROFILE%, %APPDATA% etc)
        for rootdir, dirs, files in os.walk(root, topdown=True, followlinks=False):
            # Skip paths that start with ..
            new_dirs = []
            for dir in dirs:
                skip = False
                # Generate a complete path for comparisons
                full_path = os.path.join(root, dir).lower() + os.sep
                for skip in self.SKIP_PATHS_FULL:
                    if full_path.startswith(skip):
                        logger.info(
                            f'Skipping path "{full_path}" because it starts with "{skip}"'
                        )
                        skip = True

                if not skip:
                    new_dirs.append(dir)

            dirs[:] = new_dirs

            for filename in files:
                fpath = os.path.join(root, filename)

                fstat = os.stat(fpath)
                fmode = fstat.st_mode
                if (stat.S_ISCHR(fmode)
                        or stat.S_ISBLK(fmode)
                        or stat.S_ISFIFO(fmode)
                        or stat.S_ISLNK(fmode)
                        or stat.S_ISSOCK(fmode)
                ):
                    continue

                if fstat.st_size > self._max_file_size * 1024 * 1024:
                    logger.info(f'Skipping file "{fpath}" because its size exceeds {self._max_file_size} MB')
                    continue

                try:
                    yield self._build_file_info(fpath)
                except PermissionError as e:
                    logger.warning(f'Could not scan file "{fpath}" due to permission error: {str(e)}')
                except Exception as e:
                    logger.warning(f'Could not scan file "{fpath}" due to unknown error: {str(e)}')

    def _get_all_drives(self) -> List[str]:
        return [p.mountpoint for p in psutil.disk_partitions() if p.fstype == 'NTFS']

    def _get_creation_time(self, full_path) -> Optional[datetime]:
        if OSType.is_win():
            timestamp = os.path.getctime(full_path)
        else:
            try:
                timestamp = stat.st_birthtime
            except AttributeError:
                timestamp = stat.st_mtime
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def init(config: ConfigObject):
    return FileItemHandler(config)
