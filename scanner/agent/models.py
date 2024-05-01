
from typing import Optional


from sqlalchemy import MetaData, Column, Integer, String
from sqlalchemy.types import Integer, String, Text, PickleType, LargeBinary
from sqlalchemy.ext.declarative import declarative_base

metadata = MetaData()
Base = declarative_base(metadata=metadata)


class Task(Base):

    __tablename__ = 'task'

    id = Column(Integer, primary_key=True)
    type = Column(String(32), nullable=False)
    status = Column(String(32), default='pending')  # pending, running, complete, error
    data_serialized = Column(PickleType, nullable=False)
    progress = Column(Integer, default=0)  # progress indicator (0-100)
    additional_data = Column(Text, nullable=True)

    def __init__(self, type, data):
        self.type = type
        self.data_serialized = data

    def to_dict(self):
        return {
            'id': self.id,
            'type': self.type,
            'status': self.status,
            'progress': self.progress,
            'additional_data': self.additional_data,
        }


class YaraRule(Base):

    __tablename__ = 'yara_rule'

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullabe=False)
    text = Column(Text, nullable=False)
    compiled_data = Column(LargeBinary, nullable=True)

    def __init__(self,
         name: str,
         text: Optional = None,
         compiled_data: Optional = None
    ):
        self.name = name
        self.text = text
        self.compiled_data = compiled_data

