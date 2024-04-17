import itertools
from typing import List, Tuple, Dict, Optional

from scanner.core import BaseHandler, ConditionValidator
from scanner.config import ConfigObject
from scanner.models import IndicatorItem, IndicatorItemOperator as Operator, IndicatorItemOperator

import browser_history
from urllib.parse import urlparse

from loguru import logger


class UrlItemHandler(BaseHandler):

    def __init__(self, config: ConfigObject):
        super().__init__(config)
        self._cache = dict()


    @staticmethod
    def get_supported_terms() -> list[str]:
        return [
            'UrlHistoryItem/BrowserName',
            # 'UrlHistoryItem/BrowserVersion',
            'UrlHistoryItem/URL',
            'UrlHistoryItem/PageTitle',
            'UrlHistoryItem/HostName',
            # 'UrlHistoryItem/Username'
            'UrlHistoryItem/Hidden',
            'UrlHistoryItem/VisitCount',
            # 'UrlHistoryItem/VisitFrom',  # this requires joining the referer table, which is not supported as of now
            'UrlHistoryItem/VisitType',
            'UrlHistoryItem/FirstVisitDate',
            'UrlHistoryItem/LastVisitDate',
            'UrlHistoryItem/LastVisitDateLocal',
            # 'UrlHistoryItem/Thumbnail'
            # 'UrlHistoryItem/IndexedContent'
        ]

    def validate(self, items: list[IndicatorItem], operator: IndicatorItemOperator) -> bool:
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
                output = browser.fetch_history(sort=True, desc=True)
                visits_by_url = itertools.groupby(output.histories, key=lambda v: v[1])
                for url, visits in visits_by_url:
                    visits = list(visits)

                    first_visit = min(visits, key=lambda v: v[0])[0]
                    last_visit = max(visits, key=lambda v: v[0])[0]
                    visits_count = len(visits)

                    hostname = None
                    urlobj = urlparse(url)
                    if urlobj.scheme in ['http', 'https', 'ftp']:
                        hostname = urlobj.hostname.removeprefix('www.')
                    # We use the title of the page on the first visit, although it may differ for later page visits
                    page_title = visits[0][2]
                    self._cache[url] = {
                        'BrowserName': browser.name,
                        'URL': url,
                        'PageTitle': page_title,
                        'HostName': hostname,
                        'Hidden': False,
                        'VisitCount': visits_count,
                        'VisitType': 0,
                        'LastVisitDate': last_visit,
                        'LastVisitDateLocal': last_visit,
                        'FirstVisitDateLocal': first_visit,
                    }
            except AssertionError as e:
                logger.debug(f"Browser is not installed, details: {str(e)}")
                continue
            except (PermissionError, FileNotFoundError) as e:
                logger.debug(f'Could not fetch history for {browser_class.name} browser: {str(e)}')


def init(config: ConfigObject):
    return UrlItemHandler(config)
