
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Union

class IndicatorItemOperator(Enum):
    OR = 'OR'
    AND = 'AND'

class IndicatorItemCondition(Enum):
    IS = 'is'
    CONTAINS = 'contains'
    MATCHES = 'matches'
    STARTS_WITH = 'starts-with'
    ENDS_WITH = 'ends-with'
    GREATER_THAN = 'greater-than'
    LESS_THAN = 'less-than'


@dataclass
class IndicatorItemContext:
    document: str
    search: str
    type: str

@dataclass
class IndicatorItemContent:
    type: str
    content: str

@dataclass
class IndicatorItem:
    id: str
    preserve_case: bool
    negate: bool
    condition: IndicatorItemCondition
    context: IndicatorItemContext
    content: IndicatorItemContent
@dataclass
class Indicator:
    id: str
    operator: IndicatorItemOperator
    level: int
    items: List[Union['Indicator', IndicatorItem]]

