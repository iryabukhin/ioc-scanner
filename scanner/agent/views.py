import pickle
import uuid
import io

import yara
from flask import Blueprint, jsonify, request

from .models import Task, YaraRule
from .db import db
from scanner.utils import OpenIOCXMLParser
from scanner.yara import YaraScanner, SourceType

views_blueprint = Blueprint('views', __name__)


def success(message: str, status: int = 200, data: dict = {}):
    return jsonify({'status': 'success', 'message': message, 'data': data}), status


def error(message: str, status: int = 400, data: dict = {}):
    return jsonify({'status': 'error', 'message': message, 'data': data}), status


@views_blueprint.route('/tasks/iocscan', methods=['POST'])
def create_task():
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


@views_blueprint.route('/yara/add_rule', methods=['POST'])
def yara_save():
    if not request.is_json:
        return error('Invalid request content type, must be "application/json"')

    rule_name = request.json.get('name')
    rule_text = request.json.get('text')
    vars = request.json.get('vars')

    buff = io.BytesIO()
    try:
        scanner = YaraScanner()
        scanner.compile_rules(rule_text, SourceType.STRING)
        compiled_rule = scanner.rules.save(file=buff)
        rule = YaraRule(
            name=rule_name or uuid.uuid4(),
            text=rule_text,
            compiled_data=buff.read()
        )
    except yara.Error as e:
        return error(
            'An error occurred during rule compilation',
            data={'message': str(e)}
        )

    db.session.add(rule)
    db.session.commit()
    return success('Rule saved', 201, {'rule_id': rule.id})


@views_blueprint.route('yara/<int:rule_id>/pid', methods=['POST'])
def yara_scan(rule_id: int):
    if not request.is_json:
        return error('Invalid request content type, must be "application/json"')

    variables = request.json.get('variables', {})
    pid = request.json.get('pid')

    scanner = YaraScanner(rule, SourceType.STRING)
    matches = scanner.scan_process(pid, variables)
    return success('Finished scan', 200, {'matches': matches})


@views_blueprint.route('/yara/<int:rule_id>/file', methods=['GET'])
def yara_file():
    if not request.is_json:
        return error('Invalid request content type, must be "application/json"')

    rule_id = request.json.get('rule_id')
    rule = request.json.get('rule')
    variables = request.json.get('variables', {})
    pid = request.json.get('pid')

    if not all([pid, rule_id, rule]):
        return error('Missing required parameters!')

    scanner = YaraScanner(rule, SourceType.STRING)
    matches = scanner.scan_process(pid, variables)
    return success('Finished scan', 200, {'matches': matches})
