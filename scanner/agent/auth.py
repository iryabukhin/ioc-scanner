import functools
import secrets
import uuid

from hmac import compare_digest
from typing import Optional

from .db import db

from .models import APIKey
from .exceptions import AuthorizationHeaderMissing, APIKeyError, APIKeyLookupError, APIKeyNotFound, InvalidAPIKey
from flask import request


def remove_key(key_or_uuid: str):
    keyobj = db.session.query(APIKey).filter_by(uuid=key_or_uuid).first()
    if not keyobj:
        keyobj = db.session.query(APIKey).filter_by(key=key_or_uuid).first()
    if keyobj:
        db.session.delete(keyobj)
        db.session.commit()
    else:
        raise APIKeyNotFound()


def create_key(label: Optional[str] = None) -> APIKey:
    keyobj = APIKey(label=label, key=secrets.token_urlsafe(64), uuid=str(uuid.uuid4()))
    db.session.add(keyobj)
    db.session.commit()
    return keyobj

def is_valid(api_key: str):
    keyobj = db.session.query(APIKey).filter_by(key=api_key).first()
    return keyobj and compare_digest(keyobj.key, api_key)


def api_key_required(func):
    @functools.wraps(func)
    def decorator(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            raise AuthorizationHeaderMissing()

        parts = auth_header.split(' ')
        if len(parts) != 2:
            raise APIKeyError('Malformed authentication header!')

        if parts[0] != 'Bearer':
            raise APIKeyError('Wrong header auth type!')

        full_key = parts[1]
        if is_valid(full_key):
            return func(*args, **kwargs)
        else:
            raise InvalidAPIKey()

    return decorator
