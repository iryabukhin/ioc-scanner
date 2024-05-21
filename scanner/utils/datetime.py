
from datetime import datetime, timedelta


def from_windows_timestamp(timestamp: int) -> datetime:
    return datetime(1601, 1, 1) + timedelta(microseconds=timestamp/10.)
