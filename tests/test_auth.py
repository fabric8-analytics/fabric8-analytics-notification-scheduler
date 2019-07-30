"""Tests for the 'auth' module."""

from unittest import mock
from auth import Authentication
import os


def mock_response(flag):
    """Mock the call to the auth service."""
    class MockResponse:
        """Mock response object."""

        def __init__(self, json_data, status_code, raise_status):
            """Create a mock json response."""
            self.json_data = json_data
            self.status_code = status_code
            self.raise_status = raise_status

        def json(self):
            """Get the mock json response."""
            return self.json_data

        def raise_for_status(self):
            """Get the mock json response."""
            return self.raise_status

    # return the URL to check whether we are calling the correct service.
    resp = {
        "access_token": "f98d1366-738e-4c14-a3ff-594f359e131c",
        "status": {
            "message": "",
            "code": 200,
            "attributes": {}
        },
        "result": {
            "data": [
                "a"
            ],
            "meta": {}
        }
    }

    if flag == "false":
        return MockResponse(resp, 400, "status_raised")
    elif flag == "true":
        return MockResponse(resp, 200, "")


@mock.patch("requests.post")
@mock.patch.dict(os.environ, {'AUTH_SERVICE_HOST': 'http://somehost'})
def test_init_auth_sa_token(mocker):
    """Test the function init_auth_sa_token."""
    mocker.return_value = mock_response("true")
    out = Authentication.init_auth_sa_token()
    assert out == "f98d1366-738e-4c14-a3ff-594f359e131c"

    mocker.return_value = mock_response("false")
    out = Authentication.init_auth_sa_token()
    assert out == "f98d1366-738e-4c14-a3ff-594f359e131c"


if __name__ == '__main__':
    test_init_auth_sa_token()
