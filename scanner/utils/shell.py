import os
import subprocess

from loguru import logger


def get_cmd_output(cmd: str, raise_exceptions: bool = False, **kwargs) -> str:
    try:
        run_result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            universal_newlines=True,
            shell=True,
            timeout=10,
            **kwargs
        )
        run_result.check_returncode()
        return run_result.stdout
    except subprocess.CalledProcessError as e:
        logger.warning('\n'.join([
            f'Failed to execute shell command (non-zero return code): {str(e)}',
            f'stdout: {e.stdout}',
            f'stderr: {e.stderr}',
        ]))
        if raise_exceptions:
            raise e
        else:
            return ''
    except subprocess.TimeoutExpired as e:
        logger.warning(f'Shell command timed out: {str(e)}')
        if raise_exceptions:
            raise e
        else:
            return ''
    except Exception as e:
        logger.warning(f'Unknown error occurred while executing shell command: {str(e)}')
        if raise_exceptions:
            raise e
        else:
            return ''
