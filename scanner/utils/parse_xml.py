import xml.dom
import xml.dom.minidom

import scanner.exceptions
from scanner.exceptions import XmlParseError, OpenIOCSemanticError
from scanner.models import *
from scanner.models import Indicator


class OpenIOCXMLParser:
    def __init__(self):
        self._errors = list()

    def parse(self, ioc_document_content: str) -> list[Indicator] | None:
        try:
            dom = xml.dom.minidom.parseString(ioc_document_content)
        except Exception as e:
            self._save_error(f'XML parsing error: {e}')
            return None

        try:
            ioc_id = dom.childNodes[0].getAttribute('id') if dom.childNodes[0].hasAttribute('id') else None
            criteria_nodes = dom.getElementsByTagName('criteria')
            if criteria_nodes.length == 0:
                raise OpenIOCSemanticError('Missing root <criteria> node!')

            root_node = criteria_nodes[0]
            indicators = [
                self._parse_indicator(n, 1, ioc_id) for n in root_node.childNodes
                if n.nodeType == xml.dom.Node.ELEMENT_NODE and n.tagName == 'Indicator'
            ]
            return indicators
        except OpenIOCSemanticError as e:
            self._save_error(str(e))
            return None

    def _parse_indicator(self, indicator_node, level: int = 1, parent_id: str = None) -> Indicator:
        items = []
        current_indicator_id = indicator_node.getAttribute('id')
        for child in indicator_node.childNodes:
            if child.nodeName == 'IndicatorItem':
                items.append(
                    self._parse_indicator_item(child)
                )
            elif child.nodeName == 'Indicator':
                try:
                    items.append(
                        self._parse_indicator(child, level + 1, current_indicator_id)
                    )
                except OpenIOCSemanticError as e:
                    self._save_error(str(e))
                    continue  # Continue parsing other indicators even if one fails

        return Indicator(
            id=current_indicator_id,
            operator=IndicatorItemOperator(indicator_node.getAttribute('operator')),
            level=level,
            children=items,
            parent_id=parent_id
        )

    def _parse_indicator_item(self, item_node) -> IndicatorItem:
        return IndicatorItem(
            id=item_node.getAttribute('id'),
            condition=self._parse_condition(item_node.getAttribute('condition')),
            context=self.parse_context(item_node.getElementsByTagName('Context')[0]),
            content=self._parse_content(item_node.getElementsByTagName('Content')[0]),
            negate=self._parse_boolean(item_node.getAttribute('negate')),
            preserve_case=self._parse_boolean(item_node.getAttribute('preserve-case')),
        )

    def parse_context(self, context_node) -> IndicatorItemContext:
        return IndicatorItemContext(
            document=context_node.getAttribute('document'),
            search=context_node.getAttribute('search'),
            type=context_node.getAttribute('type')
        )

    def _parse_content(self, content_node) -> IndicatorItemContent:
        return IndicatorItemContent(
            type=content_node.getAttribute('type'),
            content=content_node.firstChild.nodeValue
        )

    def _parse_condition(self, value: str) -> IndicatorItemCondition:
        try:
            return IndicatorItemCondition(value)
        except ValueError:
            raise OpenIOCSemanticError('Unknown condition type: ' + value)

    def _parse_boolean(self, value: str) -> bool:
        if value.lower() == 'true':
            return True
        elif value.lower() == 'false':
            return False
        else:
            raise XmlParseError(f'Unknown boolean attribute value: {value}')

    def _save_error(self, message: str):
        self._errors.append(message)

    def has_errors(self):
        return len(self._errors) > 0

    def get_errors(self) -> list:
        return self._errors
