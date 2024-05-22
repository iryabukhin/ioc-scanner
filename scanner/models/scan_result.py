from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime

from scanner.models import IndicatorItemOperator


@dataclass
class ValidItem:
    id: str
    type: str
    error: bool
    evaluation_mode: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    additional_data: Dict[str, str] = field(default_factory=dict)


@dataclass
class IndicatorScanResult:
    id: str
    parent_id: str
    operator: str | IndicatorItemOperator
    total_matches: int = field(default=0)
    total_unmatched: int = field(default=0)
    total_skipped: int = field(default=0)
    valid_items: list[ValidItem] = field(default_factory=list)
    skipped_items: list[ValidItem] = field(default_factory=list)
    unsupported_items: list[ValidItem] = field(default_factory=list)


@dataclass
class OpenIOCScanResult:
    result: bool
    scan_duration: int
    source: str

    scan_timestamp: datetime = field(default_factory=datetime.utcnow)

    error_logs: list[str] = field(default_factory=list)
    matches: Dict[str, IndicatorScanResult] = field(default_factory=dict)
