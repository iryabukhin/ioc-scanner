
from flask import Blueprint, jsonify, request

from .models import Task, db
from scanner.yara import YaraScanner, SourceType

views_blueprint = Blueprint('views', __name__)

@views_blueprint.route('/tasks', methods=['POST'])
def create_task():
    # Assuming the XML data is sent in the request body
    xml_data = request.data
    if not xml_data:
        return jsonify({'error': 'No XML data provided'}), 400
    task = Task(xml_data=xml_data.decode('utf-8'))
    db.session.add(task)
    db.session.commit()
    return jsonify({'message': 'Task created', 'task_id': task.id}), 201

@views_blueprint.route('/tasks/<int:task_id>', methods=['GET'])
def get_task_status(task_id):
    task = Task.query.get_or_404(task_id)
    return jsonify(task.to_dict())


@views_blueprint.route('/tasks/yara/process', methods=['POST'])
def yara_scan():
    if not request.is_json:
        return jsonify({'error': 'Invalid request content type, must be "application/json"'}), 400

    rule_id = request.json.get('rule_id')
    rule = request.json.get('rule')
    variables = request.json.get('variables', {})
    pid = request.json.get('pid')

    if not all([pid, rule_id, rule]):
        return jsonify({'error': 'Invalid request'}), 400

    scanner = YaraScanner(rule, SourceType.STRING)
    matches = scanner.process_scan(pid)
    return jsonify({'matches': matches}), 200


def yara_scan_endpoint():
    return yara_scan()
