import json
import time
import os
import pickle

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from concurrent.futures import ProcessPoolExecutor, as_completed

from .models import metadata, Task

from scanner.config import ConfigObject
from scanner.core import IOCScanner

from loguru import logger

from scanner.models import Indicator


def process_task(indicators: list[Indicator], config: ConfigObject) ->  list[str]:
    return IOCScanner(config).process(indicators)


def task_runner(config: ConfigObject, db_uri: str = None):

    if not db_uri:
        db_uri = config.get('SQLALCHEMY_DATABASE_URI')

    engine = create_engine(db_uri)
    session = Session(engine)

    logger.info('Starting task runner')

    while True:
        try:
            tasks = session.query(Task).filter_by(status='pending').all()
            if tasks:
                indicators_per_task = dict()
                for task in tasks:
                    try:
                        indicators_per_task[task] = pickle.load(task.data_serialized)
                        task.status = 'processing'
                    except Exception as e:
                        logger.error(f'Failed to deserialize task: {str(e)}')
                        task.status = 'error'
                        task.additional_data = json.dumps({'error': str(e), 'error_type': 'deserialization'})

                session.add_all(tasks)
                session.commit()

                with ProcessPoolExecutor() as executor:
                    futures_to_task = {
                        executor.submit(process_task, indicators, config): task for task, indicators in indicators_per_task.items()
                    }
                    for future in as_completed(futures_to_task):
                        try:
                            valid_indicators = future.result()
                            task = futures_to_task[future]
                            task.status = 'completed'
                            task.progress = 100
                            task.additional_data = json.dumps(valid_indicators)
                        except Exception as e:
                            task.status = 'error'
                            task.progress = 0
                            task.additional_data = json.dumps({'error': str(e)})
                        finally:
                            session.add(task)

                session.commit()

        except Exception as e:
            logger.exception(f'An error occurred while processing a task: {str(e)}')
        finally:
            time.sleep(10)