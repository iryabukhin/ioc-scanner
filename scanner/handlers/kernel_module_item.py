import os

from scanner.config import ConfigObject
from scanner.core import BaseHandler, ConditionValidator
from scanner.models import IndicatorItem, IndicatorItemOperator as Operator, ValidationResult
from scanner.utils import get_cmd_output, OSType

from loguru import logger

from scanner.utils.hash import get_file_digest


class KernelModuleHandler(BaseHandler):

    def __init__(self, config: ConfigObject):
        super().__init__(config)
        self._module_cache = {}

    @staticmethod
    def get_supported_terms() -> list[str]:
        return [
            'ModuleItem/Md5sum',
            'ModuleItem/Module',
            'ModuleItem/Size',
            'ModuleItem/UsedByList/Module',
            'ModuleItem/Status',
            'ModuleItem/Address',
            'ModuleItem/Filename',
            'ModuleItem/License',
            'ModuleItem/Retpoline',
            'ModuleItem/Vermagic',
            'ModuleItem/Intree',
        ]

    def validate(self, items: list[IndicatorItem], operator: Operator) -> ValidationResult:
        result = ValidationResult()
        result.set_lazy_evaluation(self._lazy_evaluation)

        if not OSType.is_unix() or not self._has_requred_commands():
            result.add_skipped_items(items)

        if not self._module_cache:
            self._populate_module_cache()

        for module_name, module_data in self._module_cache.items():
            for item in items:
                value = module_data.get(item.term)
                if value is not None and ConditionValidator.validate_condition(item, value):
                    result.add_matched_item(item, context={'module': module_data})
                    if operator == Operator.OR and self._lazy_evaluation:
                        result.skip_remaining_items(items)
                        return result

        return result

    def _populate_module_cache(self) -> None:
        logger.info('Populating kernel module cache...')
        modules = self._get_installed_modules()
        for module_name in modules:
            self._module_cache[module_name] = self._get_module_info(module_name)

    def _get_installed_modules(self) -> list[str]:
        output = self._get_cmd_output('lsmod')
        modules = [line.split()[0] for line in output.splitlines()[1:]]
        return modules

    def _get_module_info(self, module_name: str) -> dict:
        output = self._get_cmd_output(f'modprobe -0 {module_name}')
        parts = output.split('\0')
        if len(parts) == 0:
            logger.warning(f'No data could be extracted from "modprobe" command')
            return {}

        module_data = {}
        for part in parts:
            if ':' in part:
                k, v = part.split(':', 1)
                module_data[k.strip()] = v.strip()

        for hash_name, hash_value in get_file_digest(module_data['Filename'],  'md5', 'sha1', 'sha256'):
            module_data[f'{hash_name.upper()}sum'] = hash_value
        module_data['Size'] = os.path.getsize(module_data['Filename'])
        return module_data

    def _get_cmd_output(self, cmd: str) -> str:
        try:
            return get_cmd_output(cmd, raise_exceptions=True)
        except Exception as e:
            logger.error(f'Error executing command "{cmd}": {str(e)}')
            return ''

    def _has_requred_commands(self) -> bool:
        try:
            get_cmd_output('which lsmod', raise_exceptions=True)
            get_cmd_output('which modprobe', raise_exceptions=True)
            return True
        except Exception as e:
            logger.error('No lsmod or modprobe found on current system!')
            return False


def init(config: ConfigObject):
    return KernelModuleHandler(config)
