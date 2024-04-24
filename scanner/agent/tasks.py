import time
import os
import pickle

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from concurrent.futures import ThreadPoolExecutor, as_completed

from .models import metadata, Task

from scanner.config import ConfigObject
from scanner.core import IOCScanner

from loguru import logger


def process_task(task: Task, config: ConfigObject):
    try:
        indicators = pickle.loads(task.data_serialized)
    except pickle.PickleError as e:
        logger.error(f'Failed to deserialize task: {str(e)}')
        return

    try:
        scanner = IOCScanner(config)
        result = scanner.process(indicators)
        task.status = 'completed'
        return result
    except Exception as e:
        task.status = 'failed'
        logger.error(f'Failed to process task: {str(e)}')
        return None


def task_runner(config: ConfigObject, db_uri: str = None):

    if not db_uri:
        db_uri = config.get('SQLALCHEMY_DATABASE_URI')

    engine = create_engine(db_uri)
    session = Session(engine)

    logger.info('Starting task runner')

    while True:
        try:
            tasks = session.query(Task).filter_by(status='pending').all()
            logger.info('Fetching and running tasks..')
            if tasks:
                with ThreadPoolExecutor() as executor:
                    futures_to_task = {executor.submit(process_task, task, config): task for task in tasks}
                    for future in as_completed(futures_to_task):
                        task = futures_to_task[future]
                        result = future.result()
        except Exception as e:
            logger.exception(f'An error occurred while processing a task: {str(e)}')
        finally:
            time.sleep(10)
