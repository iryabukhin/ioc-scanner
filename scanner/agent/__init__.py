
from flask import Flask
from threading import Thread
from sqlalchemy.orm import sessionmaker
import atexit

from .models import db
from .tasks import task_runner

from scanner.config import ConfigObject


def create_app(config: ConfigObject):
    config = config.get('agent', {})
    app = Flask(__name__)
    app.config.from_mapping(config)

    db.init_app(app)

    from .views import views_blueprint
    app.register_blueprint(views_blueprint)

    task_runner_thread = Thread(target=task_runner, daemon=True, args=(config,))
    task_runner_thread.start()

    return app
