
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    xml_data = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default='pending')  # pending, running, complete, error
    progress = db.Column(db.Integer, default=0)  # Progress indicator (0-100)

    def to_dict(self):
        return {
            'id': self.id,
            'status': self.status,
            'progress': self.progress
        }