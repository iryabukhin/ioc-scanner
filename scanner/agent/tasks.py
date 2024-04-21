import time
import os
import pickle

from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy import create_engine
from concurrent.futures import ProcessPoolExecutor, as_completed
from .models import db, Task
from scanner.core import IOCScanner

from loguru import logger

def process_task(session, config, task_id):
    task = session.query(Task).get(task_id)
    if task:
        try:
            indicators = pickle.loads(task.data_serialized)
        except pickle.PickleError as e:
            logger.error(f'Failed to deserialize task: {str(e)}')
            return

        try:
            scanner = IOCScanner(config)
            result = scanner.process(indicators)
            task.status = 'completed'
        except Exception as e:
            task.status = 'failed'
            logger.error(f'Failed to process task: {str(e)}')
        finally:
            session.commit()

def task_runner(db_session, config):
    logger.info('Starting task runner')
    while True:
        try:
            tasks = db_session.query(Task).filter_by(status='pending').all()
            logger.info('Fetching and running tasks..')
            with ProcessPoolExecutor() as executor:
                futures = {executor.submit(process_task, db_session, config, task.id): task for task in tasks}
                for future in as_completed(futures):
                    result = future.result()
                    pass
        except Exception as e:
            logger.exception(f'An error occurred while processing a task: {str(e)}')
        finally:
            time.sleep(10)
