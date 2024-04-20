import time
import os

from concurrent.futures import ProcessPoolExecutor, as_completed
from . import create_app
from .models import db, Task
from scanner.core import IOCScanner

def process_task(task_id):
    app = create_app()
    with app.app_context():
        task = Task.query.get(task_id)
        if task:
            try:
                result = IOCScanner.process()  # Your processing logic here
                task.status = "completed"
            except Exception as e:
                task.status = "failed"
                # Log the error
            finally:
                db.session.commit()

def task_runner():
    while True:
        app = create_app()
        with app.app_context():
            tasks = Task.query.filter_by(status='pending').all()
            with ProcessPoolExecutor() as executor:
                futures = {executor.submit(process_task, task.id): task for task in tasks}
                for future in as_completed(futures):
                    # log task completion or handle exceptions, if any occurred
                    pass
        time.sleep(10)
