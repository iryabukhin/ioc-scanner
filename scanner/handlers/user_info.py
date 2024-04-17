from datetime import datetime as dt, timezone as tz

from scanner.config import ConfigObject
from scanner.core import BaseHandler, ConditionValidator
from scanner.models import IndicatorItem, IndicatorItemOperator as Operator
from scanner.utils import OSType

if OSType.is_win():
    import win32net, win32netcon

from loguru import logger


class UserItemHandler(BaseHandler):

    def __init__(self, config: ConfigObject):
        super().__init__(config)
        self._user_info_cache = {}

    @staticmethod
    def get_supported_terms() -> list[str]:
        return [
            'UserItem/description',
            'UserItem/disabled',
            'UserItem/fullname',
            'UserItem/homedirectory',
            'UserItem/LastLogin',
            'UserItem/lockedout',
            'UserItem/passwordrequired',
            'UserItem/scriptpath',
            'UserItem/SecurityID',
            'UserItem/SecurityType',
            'UserItem/Username',
            'UserItem/userpasswordage',
        ]

    def _fetch_all_users_info(self) -> None:
        try:
            user_list = win32net.NetUserEnum(None, 2)
            for user in user_list[0]:
                username = user['name']
                self._user_info_cache[username] = self._transform_user_info(user)
        except Exception as e:
            logger.error(f"Exception occurred while fetching all users info: {str(e)}")

    def _fetch_user_info(self, username: str) -> dict[str, str]:
        if username in self._user_info_cache:
            return self._user_info_cache[username]

        try:
            user_info = win32net.NetUserGetInfo(None, username, 2)  # Level 2 for detailed info
            self._user_info_cache[username] = self._transform_user_info(user_info)
            return self._user_info_cache[username]
        except Exception as e:
            logger.error(f"Exception occurred while fetching user info for {username}: {str(e)}")
        return {}

    def validate(self, items: list[IndicatorItem], operator: Operator) -> bool:
        if not items:
            return False

        username_item = next((item for item in items if item.context.search.endswith('Username')), None)
        if not username_item:
            logger.info("Username term was not supplied, fetching info for all users")
            self._fetch_all_users_info()
            return self._validate_against_all_users(items, operator)

        user_info = self._fetch_user_info(username_item.content.content)
        if not user_info:
            return False

        valid_items = []
        for item in items:
            value = user_info.get(item.get_term())
            if value is not None and ConditionValidator.validate_condition(item, value):
                valid_items.append(item)

        return len(valid_items) == len(items) if operator == Operator.AND else bool(valid_items)

    def _validate_against_all_users(self, items: list[IndicatorItem], operator: Operator) -> bool:
        valid_items = []
        for username, user_info in self._user_info_cache.items():
            temp_valid_items = []
            for item in items:
                value = user_info.get(item.get_term())
                if value is not None and ConditionValidator.validate_condition(item, value):
                    temp_valid_items.append(item)
            if operator == Operator.AND and len(temp_valid_items) == len(items):
                valid_items.extend(temp_valid_items)
            elif operator == Operator.OR and temp_valid_items:
                valid_items.extend(temp_valid_items)
                break
        return bool(valid_items)

    def _transform_user_info(self, raw_info: Dict) -> Dict:
        return {
            'description': raw_info.get('comment'),
            'disabled': not raw_info.get('flags') & win32netcon.UF_ACCOUNTDISABLE,
            'fullname': raw_info.get('full_name'),
            'homedirectory': raw_info.get('home_dir'),
            'LastLogin': dt.fromtimestamp(raw_info.get('last_logon')) if raw_info.get('last_logon') else None,
            'lockedout': raw_info.get('flags') & win32netcon.UF_LOCKOUT,
            'passwordrequired': not raw_info.get('flags') & win32netcon.UF_PASSWD_NOTREQD,
            'scriptpath': raw_info.get('script_path'),
            'SecurityID': None,  # Not directly available via win32net
            'SecurityType': None,  # Not directly available via win32net
            'Username': raw_info.get('name'),
            'userpasswordage': raw_info.get('password_age'),
        }

def init(config: ConfigObject):
    return UserItemHandler(config)