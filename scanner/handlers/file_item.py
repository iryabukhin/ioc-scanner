import hashlib
import os
import stat
from concurrent.futures import ThreadPoolExecutor

import psutil

from datetime import datetime, timezone

from scanner.config import ConfigObject
from scanner.core import BaseHandler, ConditionValidator
from scanner.models import (
    IndicatorItem,
    IndicatorItemOperator as Operator,
    IndicatorItemCondition as Condition, ValidationResult
)
from scanner.utils import OSType, flatten_dict
from scanner.utils.hash import get_file_digest, calculate_hash

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

        config = self.config.get('file_item', {})
        self._scan_file_hash = config.get('scan_file_hash', True)
        self._scan_all_drives = config.get('scan_all_drives', False)
        self._scan_pe_info: bool = False
        self._max_file_size = config.get('max_file_size_mb', self.MAX_FILE_SIZE_MB)
        self.file_cache = dict()

    @staticmethod
    def get_supported_terms() -> list[str]:
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
            'FileItem/PEInfo/Type',
            'FileItem/PEInfo/Subsystem',
            'FileItem/PEInfo/BaseAddress',
            'FileItem/PEInfo/PETimeStamp',
            'FileItem/PEInfo/Sections/NumberOfSections',
            'FileItem/PEInfo/Sections/ActualNumberOfSections',
            'FileItem/PEInfo/Sections/Section/Name',
            'FileItem/PEInfo/Sections/Section/Type',
            'FileItem/PEInfo/Sections/Section/SizeInBytes',
            'FileItem/PEInfo/Sections/Section/DetectedCharacteristics',
            'FileItem/PEInfo/Sections/Section/Entropy/AverageValue',
            'FileItem/PEInfo/DetectedEntryPointSignature/Name',
            'FileItem/PEInfo/DetectedEntryPointSignature/Type',
            'FileItem/PEInfo/ImportedModules/Module/Name',
            'FileItem/PEInfo/ImportedModules/Module/NumberOfFunctions',
            'FileItem/PEInfo/ImportedModules/Module/ImportedFunctions/string',
            'FileItem/PEInfo/Exports/ExportsTimeStamp',
            'FileItem/PEInfo/Exports/NumberOfFunctions',
            'FileItem/PEInfo/Exports/NumberOfNames',
            'FileItem/PEInfo/Exports/DllName',
            'FileItem/PEInfo/Exports/ExportedFunctions/string',
            'FileItem/PEInfo/DetectedAnomalies/string',
            'FileItem/PEInfo/Sections/Section/DetectedSignatureKeys/string',
            'FileItem/PEInfo/EpJumpCodes/Depth',
            'FileItem/PEInfo/EpJumpCodes/Opcodes',
            'FileItem/PEInfo/DigitalSignature/SignatureExists',
            'FileItem/PEInfo/DigitalSignature/SignatureVerified',
            'FileItem/PEInfo/DigitalSignature/Description',
            'FileItem/PEInfo/DigitalSignature/CertificateIssuer',
            'FileItem/PEInfo/DigitalSignature/CertificateSubject',
            'FileItem/PEInfo/DigitalSignature/CertificateChain',
        ]

    def _build_file_info(self, full_path: str) -> dict:
        result = {
            'FileName': os.path.basename(full_path),
            'FullPath': os.path.abspath(full_path),
            'FilePath': full_path,
            'FileExtension': os.path.splitext(full_path)[1],
            'SizeInBytes': os.path.getsize(full_path),
            'Created': self._get_creation_time(full_path),
            'Modified': datetime.fromtimestamp(os.path.getmtime(full_path), timezone.utc),
            'Accessed': datetime.fromtimestamp(os.path.getatime(full_path), timezone.utc),
        }

        if self._scan_file_hash:
            with ThreadPoolExecutor() as executor:
                hashes = executor.map(
                    lambda h: (h, calculate_hash(full_path, getattr(hashlib, h))),
                    ['md5', 'sha1', 'sha256']
                )
                result.update({f'{n.title()}sum': h for n, h in hashes})

        if self._scan_pe_info and self._is_pe_file(full_path):
            result.update(self._build_pe_info(full_path))

        return result

    def _calculate_file_hashes(self, full_path: str) -> dict[str, str]:
        hashes = get_file_digest(full_path, 'md5', 'sha1', 'sha256')
        return {f'{n.title()}sum': h for n, h in hashes.items()}

    def validate(self, items: list[IndicatorItem], operator: Operator) -> ValidationResult:
        result = ValidationResult()

        result.set_lazy_evaluation(self._lazy_evaluation)

        self._update_scan_settings(items)
        fullpath_item = next((i for i in items if i.context.search == 'FileItem/FullPath'), None)
        if fullpath_item is not None and operator is Operator.AND:
            path = fullpath_item.content.content
            path = os.path.expandvars(path)
            if path not in self.file_cache:
                self._populate_cache(path)
        elif not self.file_cache:
            self._populate_cache()

        finish = False
        for item in items:
            if finish:
                break
            for fullpath, file_data in self.file_cache.items():
                value_to_check = file_data.get(item.term)
                if value_to_check is not None and ConditionValidator.validate_condition(item, value_to_check):
                    result.add_matched_item(item, context=file_data)
                    if operator == Operator.OR and self._lazy_evaluation:
                        result.skip_remaining_items(items)
                        finish = True
                        break

        return result

    def _populate_cache(self, root: str | None = None) -> None:
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
            i['FullPath']: i for i in self._recursive_scan(root)
        }

    def _recursive_scan(self, root: str):
        logger.debug(f'Begin scanning root path "{root}" ...')
        if not os.path.exists(root):
            logger.warning(f'Path {root} does not exist, aborting scan...')
            return

        if os.path.isfile(root) and self._should_process_file(root):
            yield self._build_file_info(root)
            return

        for rootdir, dirs, files in os.walk(root, topdown=True, followlinks=False):
            dirs[:] = [d for d in dirs if not self._should_skip(os.path.join(rootdir, d))]

            for filename in files:
                fpath = os.path.join(rootdir, filename)
                if self._should_process_file(fpath):
                    try:
                        logger.debug(f'Processing file {fpath}')
                        yield self._build_file_info(fpath)
                    except PermissionError as e:
                        logger.warning(f'Could not scan file "{fpath}" due to permission error: {str(e)}')
                    except Exception as e:
                        logger.warning(f'Could not scan file "{fpath}" due to an unknown error: {str(e)}')

    def _get_all_drives(self) -> list[str]:
        return [p.mountpoint for p in psutil.disk_partitions() if p.fstype == 'NTFS']

    def _get_creation_time(self, full_path) -> datetime | None:
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

    def _update_scan_settings(self, items: list[IndicatorItem]) -> None:
        hash_terms = {'Md5sum', 'Sha1sum', 'Sha256sum'}
        # Check if any item requires hash calculation
        self._scan_file_hash = any(item.term in hash_terms for item in items)
        self._scan_pe_info = any(i.context.search.startswith('FileItem/PEInfo') for i in items)

    def _build_pe_info(self, full_path: str) -> dict:
        try:
            logger.debug(f'Begin processing PE info for file "{full_path}" ...')
            try:
                exe = pefile.PE(full_path)
            except pefile.PEFormatError as e:
                logger.warning(f'Could not process PE file "{full_path}" due to PE format error: {str(e)}')
                return {}

            info = {
                'Type': self._get_pe_type(exe),
                'Subsystem': self._get_pe_subsystem(exe),
                'BaseAddress': hex(exe.OPTIONAL_HEADER.ImageBase),
                'PETimeStamp': datetime.utcfromtimestamp(exe.FILE_HEADER.TimeDateStamp).strftime('%Y-%m-%d %H:%M:%S'),
                'NumberOfSections': exe.FILE_HEADER.NumberOfSections,
                'Sections': [{
                    'Name': section.Name.decode().rstrip('\x00'),
                    'SizeInBytes': section.SizeOfRawData,
                    'Entropy/AverageValue': section.get_entropy()
                } for section in exe.sections],
            }

            if hasattr(exe, 'DIRECTORY_ENTRY_SECURITY'):
                info['DigitalSignature'] = {'SignatureExists': True}
            else:
                info['DigitalSignature'] = {'SignatureExists': False}

            if hasattr(exe, 'DIRECTORY_ENTRY_EXPORT'):
                exports = exe.DIRECTORY_ENTRY_EXPORT
                info['Exports'] = {
                    'DllName': exports.name.decode(),
                    'NumberOfFunctions': exports.struct.NumberOfFunctions,
                    'NumberOfNames': exports.struct.NumberOfNames,
                    'ExportedFunctions': [f.name.decode() for f in exports.symbols if f.name]
                }

            if hasattr(exe, 'DIRECTORY_ENTRY_IMPORT'):
                info['Imports'] = [{
                    'DLL': imp.dll.decode(),
                    'Functions': [
                        entry.name.decode() if entry.name else 'ordinal' + str(entry.ordinal) for entry in imp.imports
                    ]
                } for imp in exe.DIRECTORY_ENTRY_IMPORT]

            if hasattr(exe, 'FileInfo'):
                info['VersionInfo'] = {}
                for fileinfo in exe.FileInfo:
                    if fileinfo.Key == b'StringFileInfo':
                        for st in fileinfo.StringTable:
                            for k, v in st.entries.items():
                                info['VersionInfo'][k.decode()] = v.decode()

            return flatten_dict(info)
        except Exception as e:
            logger.error(f'Error processing PE file {full_path}: {e}')
            return {}

    def _is_pe_file(self, full_path: str) -> bool:
        try:
            with open(full_path, 'rb') as file:
                header = file.read(2)
                if header != b'MZ':
                    return False
                file.seek(0x3C)
                pe_offset = int.from_bytes(file.read(4), 'little')
                file.seek(pe_offset)
                pe_header = file.read(4)
                return pe_header == b'PE\x00\x00'
        except Exception:
            return False

    def _get_pe_type(self, exe: pefile.PE) -> str:
        if exe.is_dll():
            return 'DLL'
        elif exe.is_exe():
            return 'EXE'
        elif exe.is_driver():
            return 'SYS'
        else:
            return 'UNKNOWN'

    def _get_pe_subsystem(self, exe: pefile.PE) -> str:
        return pefile.SUBSYSTEM_TYPE[exe.OPTIONAL_HEADER.Subsystem]


def init(config: ConfigObject):
    return FileItemHandler(config)
