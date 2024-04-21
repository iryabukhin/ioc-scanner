
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.types import Integer, String, LargeBinary

db = SQLAlchemy()


class Task(db.Model):
    id = db.Column(Integer, primary_key=True)
    type = db.Column(db.String(32), nullable=False)
    status = db.Column(db.String(32), default='pending')  # pending, running, complete, error
    data_serialized = db.Column(db.PickleType, nullable=False)
    progress = db.Column(Integer, default=0)  # progress indicator (0-100)
    additional_data = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'type': self.type,
            'status': self.status,
            'progress': self.progress,
            'additional_data': self.additional_data,
        }
