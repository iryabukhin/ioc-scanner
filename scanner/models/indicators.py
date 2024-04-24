
from dataclasses import dataclass, field
from functools import cached_property
from enum import Enum, auto
from typing import List, Union, Dict, ClassVar, Optional


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


@dataclass(frozen=True)
class IndicatorItemContext:
    document: str
    search: str
    type: str

@dataclass(frozen=True)
class IndicatorItemContent:
    type: str
    content: str


@dataclass(frozen=True)
class IndicatorItem:

    TERM_SEPARATOR: ClassVar[str] = '/'

    id: str
    preserve_case: bool
    negate: bool
    condition: IndicatorItemCondition
    context: IndicatorItemContext
    content: IndicatorItemContent

    @cached_property
    def all_terms(self) -> list[str]:
        return self.context.search.split(self.TERM_SEPARATOR)

    @cached_property
    def type(self) -> str:
        return self.all_terms[0]

    @cached_property
    def term(self) -> str:
        return self.all_terms[-1]
    def has_subterms(self) -> bool:
        terms = [t for t in self.all_terms if t != self.context.document]
        return len(terms) > 1


@dataclass(frozen=True)
class Indicator:
    id: str
    operator: IndicatorItemOperator
    level: int
    items: list[Union['Indicator', IndicatorItem]]
    parent_id: str | None = field(default=None)

