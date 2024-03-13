
from scanner.utils import parse

FILEPATH = 'iocs/0294496a-b037-55b9-a3fe-46a344d7f524.xml'

with open(FILEPATH, 'r') as f:
    try:
        content = f.read()
        indicators = parse(content)
    except Exception as e:
        print(
            f'An error occurred while parsing XML: ' + str(e)
        )