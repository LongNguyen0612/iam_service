from fastapi import status
from libs.result import Error


class ClientError(Exception):
    def __init__(self, base_error: Error, status_code: int = status.HTTP_400_BAD_REQUEST):
        self.base_error = base_error
        self.status_code = status_code
        super().__init__(base_error.message)


class ServerError(Exception):
    def __init__(self, base_error: Error):
        self.base_error = base_error
        super().__init__(base_error.message)
