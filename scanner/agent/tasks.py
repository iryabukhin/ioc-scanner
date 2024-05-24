import json
import threading
import pickle

import sqlalchemy.pool


from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from concurrent.futures import ProcessPoolExecutor, as_completed

from .models import Task

from scanner.config import ConfigObject
from scanner.core import IOCScanner
from scanner.models import Indicator, OpenIOCScanResult

from loguru import logger


def process_task(indicators: list[Indicator], config: ConfigObject) -> OpenIOCScanResult:
    logger.remove()
    logger.add(sink=f'task_runner_{"_".join([i.id for i in indicators if i.level == 1])}.log')
    with logger.contextualize(thread_id=threading.get_native_id(), task='openioc'):
        result = IOCScanner(config).process(indicators)
    return result


@logger.contextualize(thread_id=threading.get_native_id(), app='task_runner')
def task_runner(config: ConfigObject, db_uri: str = None):

    if not db_uri:
        db_uri = config.get('SQLALCHEMY_DATABASE_URI')

    engine = create_engine(db_uri, poolclass=sqlalchemy.pool.NullPool)
    session = Session(engine)

    logger.info('Starting task runner')

    from . import shutdown_event

    while not shutdown_event.is_set():
        try:
            tasks = session.query(Task).filter_by(status='pending').all()
            if tasks:
                indicators_per_task = dict()
                for task in tasks:

                    logger.info(f'Begin processing tasks: ' + ', '.join([str(task.id) for task in tasks]))

                    try:
                        indicators_per_task[task] = pickle.loads(task.data_serialized)
                        task.status = 'processing'
                    except Exception as e:
                        logger.error(f'Failed to deserialize task (task_id={task.id}): {str(e)}')
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
                            scan_result: OpenIOCScanResult = future.result()
                            task = futures_to_task[future]
                            task.status = 'completed'
                            task.progress = 100
                            task.additional_data = scan_result.to_json()
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
            if shutdown_event.wait(timeout=10):
                logger.info('Received shutdown event')
                session.close()
                engine.dispose()
