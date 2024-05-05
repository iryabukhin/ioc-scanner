import pickle
import uuid
import io

import yara

from typing import Optional

from pydantic import BaseModel

from flask import Blueprint, jsonify, request
from flask_pydantic import validate
from sqlalchemy import select, and_,  or_

from .models import Task, YaraRule
from .db import db
from .auth import api_key_required

from scanner.utils import OpenIOCXMLParser
from scanner.yara import YaraScanner, SourceType

views_blueprint = Blueprint('views', __name__)


def success(message: str, status: int = 200, data=None):
    if data is None:
        data = {}
    return jsonify({'status': 'success', 'message': message, 'data': data}), status


def error(message: str, status: int = 400, data=None):
    if data is None:
        data = {}
    return jsonify({'status': 'error', 'message': message, 'data': data}), status

def fetch_rule(name_or_id: str):
    return db.one_or_404(
        db.select(YaraRule).where(or_(
            YaraRule.id == name_or_id,
            YaraRule.name == name_or_id
        ))
    )


@views_blueprint.route('/tasks/iocscan', methods=['POST'])
def create_task():
    if request.content_type not in ['application/xml', 'application/xhtml+xml']:
        return error('Invalid request content type, must be "application/xml" or "application/xhtml+xml"')

    # Assuming the XML data is sent in the request body
    xml_data = request.data
    if not xml_data:
        return error('No XML data provided')

    parser = OpenIOCXMLParser()
    indicators = parser.parse(xml_data.decode())

    errors = parser.get_errors()
    if errors:
        return error(
            'Some errors occurred during parsing of XML',
            400, {'errors': errors}
        )

    if not indicators:
        return error('XML is correct, but no indicators were found')

    task = Task(type='openioc', data=pickle.dumps(indicators))
    db.session.add(task)
    db.session.commit()
    return success('Task created', 201, {'task_id': task.id})


@views_blueprint.route('/tasks/<int:task_id>', methods=['GET'])
def get_task_status(task_id: int):
    task = Task.query.get_or_404(task_id)
    return jsonify(task.to_dict())


@views_blueprint.route('/yara/rules', methods=['GET'])
@api_key_required
def yara_list_all():
    all_rules = db.session.query().with_entities(YaraRule.id, YaraRule.name, YaraRule.text)
    rules = {rule[0]: rule[1] for rule in all_rules}
    return success('fetched all rules', data={'rules': rules})


class YaraRuleCreateRequestBody(BaseModel):
    text: str
    name: Optional[str]
    variables: Optional[dict] = {}


@views_blueprint.route('/yara/add_rule', methods=['POST'])
@api_key_required
@validate()
def yara_save(body: YaraRuleCreateRequestBody):
    buffer = io.BytesIO()
    try:
        scanner = YaraScanner()
        scanner.compile_rules(body.text, SourceType.STRING, body.variables)
        scanner.rules.save(file=buffer)
        buffer.seek(0)
        rule = YaraRule(
            name=body.name or str(uuid.uuid4()),
            text=body.text,
            compiled_data=buffer.read()
        )
    except yara.Error as e:
        return error(
            'An error occurred during rule compilation',
            data={'message': str(e)}
        )

    db.session.add(rule)
    db.session.commit()
    return success('Rule saved', 201, {'rule_id': rule.id})



class YaraScanRequestBody(BaseModel):
    variables: Optional[dict] = {}

class YaraProcessScanRequestBody(YaraScanRequestBody):
    pid: int

class YaraFileScanRequestBody(YaraScanRequestBody):
    filepath: str


@views_blueprint.route('/yara/<rule_id_or_name>/pid', methods=['POST'])
@api_key_required
@validate(body=YaraProcessScanRequestBody)
def yara_scan(rule_id_or_name: str, body: YaraProcessScanRequestBody):
    rule = fetch_rule(rule_id_or_name)
    try:
        scanner = YaraScanner()
        scanner.load_compiled_rules(rule.compiled_data)
    except yara.Error as e:
        return error(f'Failed to load pre-compiled Yara rule "{rule_id_or_name}"')

    try:
        matches = scanner.scan_process(body.pid, body.variables)
    except PermissionError as e:
        return error('Unable to perform a scan due to a permission error', data={'errmsg': str(e)})
    except Exception as e:
        return error('Unable to perform a scan due to an unknown error', data={'errmsg': str(e)})

    return success('Scan finished', 200, {'matches': matches})


@views_blueprint.route('/yara/<rule_id_or_name>/file', methods=['POST'])
@api_key_required
@validate(body=YaraFileScanRequestBody)
def yara_file(rule_id_or_name: str, body: YaraFileScanRequestBody):
    rule = fetch_rule(rule_id_or_name)
    try:
        scanner = YaraScanner()
        scanner.load_compiled_rules(rule.compiled_data)
    except yara.Error as e:
        return error(f'Failed to load pre-compiled Yara rule "{rule_id_or_name}"', data={'errmsg': str(e)})

    try:
        matches = scanner.scan_file(body.filepath, body.variables)
    except PermissionError as e:
        return error('Unable to performa a scan due to a permission error', data={'errmsg': str(e)})
    except Exception as e:
        return error('Unable to performa a scan due to an unknown error', data={'errmsg': str(e)})

    return success('Scan finished', 200, {'matches': matches})
