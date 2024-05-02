from flask import Flask
from werkzeug.serving import is_running_from_reloader

import threading
import atexit

from .db import db
from .tasks import task_runner

from scanner.config import ConfigObject

shutdown_event = threading.Event()


def create_app(config: ConfigObject):
    config = config.get('agent', {})
    app = Flask(__name__)
    app.config.from_mapping(config)

    db.init_app(app)

    from .views import views_blueprint
    app.register_blueprint(views_blueprint)

    if not is_running_from_reloader():
        task_runner_thread = threading.Thread(target=task_runner, args=(config,), name='task_runner')
        def shutdown_task_runner():
            shutdown_event.set()
            task_runner_thread.join()

        atexit.register(shutdown_task_runner)
        task_runner_thread.start()

    return app
