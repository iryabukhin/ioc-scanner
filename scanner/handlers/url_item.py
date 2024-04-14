import os
from typing import List, Tuple, Dict, Optional

from scanner.core import BaseHandler, ConditionValidator
from scanner.config import ConfigObject
from scanner.models import IndicatorItem, IndicatorItemOperator as Operator, IndicatorItemOperator
from scanner.utils import OSType

import browser_history
from urllib.parse import urlparse

from loguru import logger

class UrlItemHandler(BaseHandler):
    def __init__(self, config: ConfigObject):
        super().__init__(config)
        self._cache = dict()


    @staticmethod
    def get_supported_terms() -> List[str]:
        return [
            'UrlHistoryItem/BrowserName',
            'UrlHistoryItem/BrowserVersion',
            'UrlHistoryItem/URL'
            'UrlHistoryItem/PageTitle'
            'UrlHistoryItem/HostName'
            'UrlHistoryItem/Username'
            'UrlHistoryItem/Hidden'
            'UrlHistoryItem/VisitCount'
            'UrlHistoryItem/VisitFrom'
            'UrlHistoryItem/VisitType'
            'UrlHistoryItem/LastVisitDate'
            'UrlHistoryItem/LastVisitDateLocal'
            'UrlHistoryItem/FirstVisitDateLocal'
            'UrlHistoryItem/Thumbnail'
            'UrlHistoryItem/IndexedContent'
        ]

    def validate(self, items: List[IndicatorItem], operator: IndicatorItemOperator) -> bool:
        if not self._cache:
            self._fill_cache()

        valid_items = set()
        for url, url_data in self._cache.items():
            for item in items:
                term = item.get_term()
                value = url_data.get(term)
                if value is not None and ConditionValidator.validate_condition(item, value):
                    if operator == Operator.OR:
                        return True
                    valid_items.add(item)
        return operator == Operator.AND and len(valid_items) == len(items)

    def _fill_cache(self):
        for browser_class in browser_history.utils.get_browsers():
            try:
                browser = browser_class()
                outputs = browser.fetch_history()
                for entry in outputs.histories:
                    last_visit, url, title = entry
                    self._cache[url] = {
                        'BrowserName': browser.name,
                        'URL': url,
                        'PageTitle': title,
                        'HostName': urlparse(url).hostname,
                        'Username': entry[2],
                        'Hidden': entry[3],
                        'LastVisitDate': last_visit,
                        'LastVisitDateLocal': last_visit.astimezone(tz=None),
                    }
            except AssertionError as e:
                logger.debug(f"Browser is not installed, details: {str(e)}")
                continue
            except PermissionError as e:
                name = browser.name if browser is not None else browser_class.__class__.__name__
                logger.debug(f'Could not fetch history for {name} browser: {str(e)}')



def init(config: ConfigObject):
    pass