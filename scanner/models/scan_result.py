from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime

from scanner.models import IndicatorItemOperator as Operator, Indicator, IndicatorItem



@dataclass
class IndicatorScanResult:
    id: str
    parent_id: str
    operator: str | Operator
    children_count: int
    overall_valid: bool = False
    total_matches: int = field(default=0)
    total_unmatched: int = field(default=0)
    total_skipped: int = field(default=0)
    valid_items: list[IndicatorItem] = field(default_factory=list)
    skipped_items: list[IndicatorItem] = field(default_factory=list)
    # unsupported_items: list[IndicatorItem] = field(default_factory=list)
    match_data: dict = field(default_factory=dict)

    def add_valid_item(self, item: IndicatorItem):
        self.valid_items.append(item)
        self.total_matches += 1

    def add_skipped_item(self, item: IndicatorItem):
        self.skipped_items.append(item)
        self.total_skipped += 1

    def update_valid_status(self):
        if self.operator == Operator.OR:
            status = len(self.valid_items) > 0
        else:
            status = self.children_count == (self.total_matches + self.total_skipped)

        self.overall_valid = status


    @classmethod
    def from_indicator_object(cls, indicator: Indicator):
        return cls(
            id=indicator.id,
            parent_id=indicator.parent_id,
            operator=indicator.operator,
            children_count=len(indicator.children)
        )

    def merge(self, other: 'IndicatorScanResult'):
        self.total_matches += other.total_matches
        self.total_unmatched += other.total_unmatched
        self.total_skipped += other.total_skipped
        self.valid_items += other.valid_items
        self.skipped_items += other.skipped_items
        self.overall_valid = self.overall_valid or other.overall_valid \
            if self.operator == Operator.OR \
            else self.overall_valid and other.overall_valid
        return self


@dataclass
class OpenIOCScanResult:
    result: bool
    # source: str
    # scan_duration: Optional[int] = field(default=None)
    # scan_timestamp: datetime = field(default_factory=datetime.utcnow)
    error_logs: list[str] = field(default_factory=list)
    matches: list[dict] = field(default_factory=list)

