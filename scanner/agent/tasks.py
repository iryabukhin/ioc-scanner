import os

from celery import shared_task
from flask import current_app
from flask_sqlalchemy import SQLAlchemy

from.models import db, Task
from scanner.core import IOCScanner
from scanner.utils import parse_xml



@shared_task(name='tasks.scan_message')
def scan_message(xml_data):
    try:
        indicator = parse_xml(xml_data)
    except Exception as e:
        current_app.logger.error(f'Unable to parse OpenIoC document content: {str(e)}')
        return
    db.session.add(indicator)
    db.session.commit()
    return indicator.to_dict()


@shared_task(name='tasks.get_scan_results')
def get_scan_results():
    indicators = Task.query.all()
    return [indicator.to_dict() for indicator in indicators]