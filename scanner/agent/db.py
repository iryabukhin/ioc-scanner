
from flask_sqlalchemy import SQLAlchemy

from .models import metadata

db = SQLAlchemy(metadata=metadata)