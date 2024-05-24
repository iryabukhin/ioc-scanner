from scanner.core import BaseHandler, ConditionValidator
from scanner.models import (
    IndicatorItem,
    IndicatorItemOperator as Operator,
    IndicatorItemCondition as Condition, ValidationResult
)
from scanner.config import ConfigObject
from scanner.utils import from_windows_timestamp

from loguru import logger

import os
import struct
import windowsprefetch


class PrefetchItemHandler(BaseHandler):

    PREFETCH_DIR = os.path.join(os.environ['SYSTEMROOT'], 'Prefetch')

    def __init__(self, config: ConfigObject):
        super().__init__(config)

    @staticmethod
    def get_supported_terms() -> list[str]:
        return [
            'PrefetchItem/FullPath',
            'PrefetchItem/SizeInBytes'
            'PrefetchItem/ReportedSizeInBytes'
            'PrefetchItem/Created',
            'PrefetchItem/PrefetchHash',
            'PrefetchItem/ApplicationFileName',
            'PrefetchItem/LastRun',
            'PrefetchItem/TimesExecuted',
            'PrefetchItem/AccessedFileList/AccessedFile',
            'PrefetchItem/VolumeList/VolumeItem/DevicePath',
            'PrefetchItem/VolumeList/VolumeItem/CreationTime',
            'PrefetchItem/VolumeList/VolumeItem/SerialNumber',
        ]

    def validate(self, items: list[IndicatorItem], operator: Operator) -> ValidationResult:
        result = ValidationResult()
        result.set_lazy_evaluation(self._lazy_evaluation)

        for item in items:
            for pf_file in self._get_prefetch_files():
                try:
                    pf_data = self._parse_prefetch_file(pf_file)
                except Exception as e:
                    errmsg = f'Could not fetch data about a Prefetch file {pf_file}: ' + str(e)
                    logger.error(errmsg)
                    continue

                if self._validate_single_item(pf_data, item):
                    result.add_matched_item(item, context={'pf_file': pf_file})
                    if Operator == Operator.OR and self._lazy_evaluation:
                        result.add_skipped_items(items)
                        return result

        return result

    def _get_prefetch_files(self) -> list[str]:
        return [os.path.join(self.PREFETCH_DIR, f) for f in os.listdir(self.PREFETCH_DIR) if f.endswith('.pf')]

    def _parse_prefetch_file(self, path: str) -> dict:
        pf = windowsprefetch.Prefetch(path)
        data = {
            'FullPath': os.path.abspath(path),
            'SizeInBytes': os.path.getsize(path),
            'ReportedSizeInBytes': pf.fileSize,
            'PrefetchHash': pf.hash,
            'ApplicationFileName': pf.executableName,
            'TimesExecuted': pf.runCount,
            'LastRun': from_windows_timestamp(struct.unpack('Q', pf.lastRunTime)[0]),
            'VolumeList': [],
            'AccessedFileList': []
        }

        for volume in pf.volumesInformationArray:
            volume_item = {}
            volume_item['DevicePath'] = volume['Volume Name'].decode('utf-16le')
            volume_item['CreationTime'] = volume['Creation Date']
            volume_item['SerialNumber'] = volume['Serial Number']
            data['VolumeList'].append(volume_item)

        data['AccessedFileList'] = []
        for fileitem in pf.filenames:
            data['AccessedFile'] = fileitem

        return data

    def _validate_single_item(self, pf_data: dict, item: IndicatorItem) -> bool:

        term = item.context.search.removeprefix('PrefetchItem/')
        if term.startswith('VolumeList/'):
            value = pf_data['VolumeList']
        elif term.startswith('AccessedFileList/'):
            value = pf_data['AccessedFileList']
        else:
            value = pf_data.get(term)

        result = ConditionValidator.validate_condition(item, value)
        return result


def init(config: ConfigObject):
    return PrefetchItemHandler(config)
