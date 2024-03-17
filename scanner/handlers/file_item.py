import os
import stat
import hashlib
from typing import Union, Optional, List, Dict, ByteString

from scanner.core import BaseHandler
from scanner.models import IndicatorItem, IndicatorItemOperator, IndicatorItemContext, IndicatorItemContent

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

HASH_CHUNK_SIZE = 4096


def calculate_hash(file_path: str, hash_method):
    hash_obj = hash_method()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(HASH_CHUNK_SIZE), b""):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()


class FileItemHandler(BaseHandler):

    def __init__(self):
        self.file_cache = {}
        self.default_root_path = '/'

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
        return {
            'FileItem/FileName': os.path.basename(full_path),
            'FileItem/FilePath': os.path.abspath(full_path),
            'FileItem/FileExtension': os.path.splitext(full_path)[1],
            'FileItem/SizeInBytes': os.path.getsize(full_path),
            'FileItem/Md5sum': calculate_hash(full_path, hashlib.md5),
            'FileItem/Sha1sum': calculate_hash(full_path, hashlib.sha1),
            'FileItem/Sha256sum': calculate_hash(full_path, hashlib.sha256),
        }

    def _populate_cache(self) -> None:
        self.file_cache = {
            i['FileItem/FilePath'] for i in self._full_scan_filesystem(self.default_root_path)
        }

    def validate(self, items: List[IndicatorItem], operator: IndicatorItemOperator) -> bool:
        if not self.file_cache:
            self._populate_cache()

        # TODO: Implement better validation logic here
        for item in items:
            term = item['term']
            value = item['value']
            for file_path, file_info in self.file_cache.items():
                if term in file_info and file_info[term] == value:
                    return True
        return False

    def _full_scan_filesystem(self, root: str) -> List[Dict]:
        # TODO: Add extensive logging to this method
        if not os.path.exists(root):
            return []

        for rootdir, dirs, files in os.walk(root, topdown=True, followlinks=False):
            # Skip paths that start with ..
            new_dirs = []
            for dir in dirs:
                skip = False
                # Generate a complete path for comparisons
                full_path = os.path.join(root, dir).lower() + os.sep
                for skip in SKIP_PATHS_FULL:
                    if full_path.startswith(skip):
                        skip = True

                if not skip:
                    new_dirs.append(dir)

            dirs[:] = new_dirs

            for filename in files:
                fpath = os.path.join(root, filename)

                fmode = os.stat(fpath).st_mode
                if (stat.S_ISCHR(fmode)
                        or stat.S_ISBLK(fmode)
                        or stat.S_ISFIFO(fmode)
                        or stat.S_ISLNK(fmode)
                        or stat.S_ISSOCK(fmode)
                ):
                    continue

                yield self._build_file_info(fpath)


def init():
    return (
        FileItemHandler(),
        FileItemHandler.get_supported_terms()
    )
