import os
import stat
import hashlib
from typing import Union, Optional, List, Dict, ByteString

from scanner.core import BaseHandler, ConditionValidator
from scanner.models import IndicatorItem, IndicatorItemOperator as Operator
from scanner.utils.hash import calculate_hash

from loguru import logger


HASH_CHUNK_SIZE = 4096


class FileItemHandler(BaseHandler):
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

    MAX_FILE_SIZE = 1024 * 1024 * 1024

    def __init__(self):
        self.file_cache = {}
        self.default_root_path = '/'
        self.scan_all_drives = False


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
            'FileItem/SizeInBytes'
        ]

    def _build_file_info(self, full_path: str) -> Dict:
        result = {
            'FileName': os.path.basename(full_path),
            'FilePath': os.path.abspath(full_path),
            'FileExtension': os.path.splitext(full_path)[1],
            'SizeInBytes': os.path.getsize(full_path),
        }

        hash_methods = [hashlib.md5(), hashlib.sha1(), hashlib.sha256()]
        with open(full_path, 'rb') as f:
            for chunk in iter(lambda: f.read(HASH_CHUNK_SIZE), b""):
                for hash_obj in hash_methods:
                    hash_obj.update(chunk)
        result.update({f'{h.name.title()}sum': hash_obj.hexdigest() for h in hash_methods})
        return result

    def _populate_cache(self) -> None:
        self.file_cache = {
            i['FileItem/FilePath'] for i in self._full_scan_filesystem(self.default_root_path)
        }

    def validate(self, items: List[IndicatorItem], operator: Operator) -> bool:
        if not self.file_cache:
            self._populate_cache()

        valid_items = list()
        # TODO: Implement better validation logic here
        for item in items:
            term = item.context.search
            value = self.file_cache.get(term)
            if value is not None and ConditionValidator.validate_condition(item, value):
                valid_items.append(item)

        return bool(valid_items) if operator is Operator.OR else len(valid_items) == len(items)

    def get_value_by_term(self, term: str) -> Optional[Union[str, int]]:
        file_info = self.file_cache.get(term)
        if file_info:
            return file_info.get(term.split('/')[-1])
        return None

    def _full_scan_filesystem(self, root: str) -> List[Dict]:
        # TODO: Add extensive logging to this method
        logger.info(f'Begin scanning root path "{root}"')
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

                stat = os.stat(fpath)
                fmode = stat.st_mode
                if (stat.S_ISCHR(fmode)
                        or stat.S_ISBLK(fmode)
                        or stat.S_ISFIFO(fmode)
                        or stat.S_ISLNK(fmode)
                        or stat.S_ISSOCK(fmode)
                ):
                    continue

                if stat.st_size > self.MAX_FILE_SIZE:
                    logger.info(f'Skipping file "{fpath}" because its size exceeds {self.MAX_FILE_SIZE} bytes')
                    continue

                yield self._build_file_info(fpath)


def init():
    return (
        FileItemHandler(),
        FileItemHandler.get_supported_terms()
    )
