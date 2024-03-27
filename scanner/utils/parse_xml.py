

from typing import List, Dict, Union, Optional
from collections import defaultdict
import xml.dom
import xml.dom.minidom

import scanner.exceptions
from scanner.exceptions import XmlParseError, OpenIOCSemanticError
from scanner.models import *
from scanner.models import Indicator


def parse(ioc_document_content: str) -> List[Indicator]:
    try:
        dom = xml.dom.minidom.parseString(ioc_document_content)
    except Exception as e:
        # TODO: add logging output
        raise XmlParseError(f'Unable to parse OpenIoC document content: {e}')

    criteria_nodes = dom.getElementsByTagName('criteria')
    if criteria_nodes.length == 0:
        raise scanner.exceptions.OpenIOCSemanticError(
            'Missing root <criteria> node!'
        )

    root_node = criteria_nodes[0]
    return [
        parse_indicator(n) for n in root_node.childNodes
        if n.nodeType == xml.dom.Node.ELEMENT_NODE and n.tagName == 'Indicator'
    ]


def parse_indicator(indicator_node, level: int = 1):
    items = []
    for child in indicator_node.childNodes:
        if child.nodeName == 'IndicatorItem':
            items.append(
                parse_indicator_item(child)
            )
        elif child.nodeName == 'Indicator':
            items.append(
                parse_indicator(child, level + 1)
            )

    return Indicator(
        id=indicator_node.getAttribute('id'),
        operator=IndicatorItemOperator(indicator_node.getAttribute('operator')),
        level=level,
        items=items,
    )


def parse_indicator_item(item_node) -> IndicatorItem:
    return IndicatorItem(
        id=item_node.getAttribute('id'),
        condition=parse_condition(item_node.getAttribute('condition')),
        context=parse_context(item_node.getElementsByTagName('Context')[0]),
        content=parse_content(item_node.getElementsByTagName('Content')[0]),
        negate=item_node.getAttribute('negate'),
        preserve_case=item_node.getAttribute('preserve-case')
    )


def parse_context(context_node) -> IndicatorItemContext:
    return IndicatorItemContext(
        document=context_node.getAttribute('document'),
        search=context_node.getAttribute('search'),
        type=context_node.getAttribute('type')
    )

def parse_content(content_node) -> IndicatorItemContent:
    return IndicatorItemContent(
        type=content_node.getAttribute('type'),
        content=content_node.firstChild.nodeValue
    )

def parse_condition(value: str) -> IndicatorItemCondition:
    try:
        return IndicatorItemCondition(value)
    except ValueError:
        raise OpenIOCSemanticError('Unknown condition type: ' + value)
