
class APIKeyError(Exception):
    def __init__(self, message=None, status_code=None):
        if message is not None:
            self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.title = self.__class__.__name__


class AuthorizationHeaderMissing(APIKeyError):
    status_code = 401
    message = 'Missing Authorization header.'


class InvalidAPIKey(APIKeyError):
    message = 'The provided API key is invalid.'
    status_code = 401


class APIKeyLookupError(APIKeyError):
    message = 'An exception occurred during user-supplied API key lookup'
    status_code = 502


class APIKeyNotFound(APIKeyError):
    message = 'APIKey not found.'
    status_code = 404
