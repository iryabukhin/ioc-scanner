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


def process_task(task: Task, config: ConfigObject) -> tuple[Task, list[str]]:
    try:
        indicators = pickle.loads(task.data_serialized)
    except pickle.PickleError as e:
        logger.error(f'Failed to deserialize task: {str(e)}')
        return

    try:
        scanner = IOCScanner(config)
        result = scanner.process(indicators)
        task.status = 'completed'
        return task, result
    except Exception as e:
        task.status = 'failed'
        logger.error(f'Failed to process task: {str(e)}')
        return task, []


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
                        task, valid_indicators = futures_to_task[future]
                        session.add(task)
                    session.commit()
        except Exception as e:
            logger.exception(f'An error occurred while processing a task: {str(e)}')
        finally:
            time.sleep(10)
