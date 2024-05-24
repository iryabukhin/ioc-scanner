
from dataclasses import dataclass, field
from dataclasses_json import dataclass_json
from datetime import datetime
from functools import cached_property
from enum import Enum, auto
from typing import Union, ClassVar, Optional


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


@dataclass_json()
@dataclass(frozen=True)
class IndicatorItemContext:
    document: str
    search: str
    type: str

@dataclass_json()
@dataclass(frozen=True)
class IndicatorItemContent:
    type: str
    content: str

@dataclass_json
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


@dataclass_json
@dataclass(frozen=True)
class Indicator:
    id: str
    operator: IndicatorItemOperator
    level: int
    children: list[Union['Indicator', IndicatorItem]]
    parent_id: str | None = field(default=None)

    @cached_property
    def child_items(self) -> list[IndicatorItem]:
        return [i for i in self.children if isinstance(i, IndicatorItem)]

    @cached_property
    def child_indicators(self) -> list['Indicator']:
        return [i for i in self.children if isinstance(i, Indicator)]


@dataclass_json
@dataclass
class ValidationResult:
    matched_items: list[IndicatorItem] = field(default_factory=list)
    skipped_items: list[IndicatorItem] = field(default_factory=list)
    error_items: list[IndicatorItem] = field(default_factory=list)

    error_logs: list[str] = field(default_factory=list)

    evaluation_mode: str = field(default='eager')

    item_context: dict[str, dict] = field(default_factory=dict)
    artifact_info: dict[str, dict] = field(default_factory=dict)


    def add_matched_item(self, item: IndicatorItem, context: Optional[dict] = None):
        self.matched_items.append(item)
        self.item_context[item.id] = context if context is not None else {}

    def add_skipped_items(self, items: IndicatorItem | list[IndicatorItem]):
        items = items if isinstance(items, list) else [items]
        self.skipped_items.extend(items)

    def skip_remaining_items(self, items_to_skip: IndicatorItem | list[IndicatorItem]):
        items = items_to_skip if isinstance(items_to_skip, list) else [items_to_skip]
        self.skipped_items.extend([i for i in items if i not in self.matched_items])

    def add_error_items(self, items: IndicatorItem | list[IndicatorItem], error_message: str):
        self.error_items.extend(items if isinstance(items, list) else [items])
        self.error_logs.append(error_message)

    def add_item_artifact_info(self, item: IndicatorItem, artifact_info: dict):
        self.artifact_info[item.id] = artifact_info

    def set_lazy_evaluation(self, flag: bool):
        self.evaluation_mode = 'lazy' if flag else 'eager'

    def merge(self, other: 'ValidationResult'):
        self.matched_items.extend(other.matched_items)
        self.skipped_items.extend(other.skipped_items)
        self.error_items.extend(other.error_items)
        self.error_logs.extend(other.error_logs)
        self.artifact_info.update(other.artifact_info)
        self.item_context.update(other.item_context)


@dataclass_json()
@dataclass
class IndicatorValidationResult:
    valid: bool
    valid_items: list[IndicatorItem] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def merge(self, other: 'IndicatorValidationResult'):
        self.valid = self.valid and other.valid
        self.valid_items.extend(other.valid_items)
        self.errors.extend(other.errors)
        self.warnings.extend(other.warnings)

