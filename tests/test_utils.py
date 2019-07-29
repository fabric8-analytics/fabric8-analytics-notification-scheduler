"""Tests for the 'utils' module."""

from unittest import mock
from utils import execute_gremlin_dsl, select_latest_version,\
    get_response_data, check_license_conflict


@mock.patch("utils.get_session_retry")
def test_check_license_conflict(mocker):
    """Test the function check_license_conflict."""
    payload = {"a": "b"}
    mocker.return_value = MockedSession("lic_true")
    out = check_license_conflict(payload)
    assert out == "false"

    mocker.return_value = MockedSession("lic_false")
    out = check_license_conflict(payload)
    assert out == "true"


def test_execute_gremlin_dsl2():
    """Test the function execute_gremlin_dsl."""
    query_str = "g.V().has('ecosystem', eco).has('name',pkg).valueMap()"
    payload = {
        'gremlin': query_str,
        'bindings': {
            'eco': 'maven',
            'pkg': 'io.vertx:vertx-web'
        }
    }
    out = execute_gremlin_dsl(payload)
    assert out is None


@mock.patch("utils.get_session_retry")
def test_execute_gremlin_dsl(mocker):
    """Test the function execute_gremlin_dsl."""
    mocker.return_value = ""
    query_str = "g.V().has('ecosystem', eco).has('name',pkg).valueMap()"
    payload = {
        'gremlin': query_str,
        'bindings': {
            'eco': 'maven',
            'pkg': 'io.vertx:vertx-web'
        }
    }
    out = execute_gremlin_dsl(payload)
    assert out is None

    mocker.return_value = MockedSession("true")
    out = execute_gremlin_dsl(payload)
    assert out['requestId'] == "f98d1366-738e-4c14-a3ff-594f359e131c"

    out = get_response_data(out, [{0: 0}])
    assert "a" in out

    mocker.return_value = MockedSession("false")
    query_str = "g.V().has('ecosystem', eco).has('name',pkg).valueMap()"
    payload = {
        'gremlin': query_str,
        'bindings': {
            'eco': 'maven',
            'pkg': 'io.vertx:vertx-web'
        }
    }
    out = execute_gremlin_dsl(payload)
    assert out is None


class MockedSession:
    """Mocked session object used by the following test."""

    def __init__(self, flag):
        """Construct instance of this class."""
        self.id = None
        self.flag = flag

    def post(self, url="http://", data=None):
        """Get post value."""
        print(url)
        print(data)
        return mock_response(self.flag)


def mock_response(flag):
    """Mock the call to the insights service."""
    class MockResponse:
        """Mock response object."""

        def __init__(self, json_data, status_code):
            """Create a mock json response."""
            self.json_data = json_data
            self.status_code = status_code

        def json(self):
            """Get the mock json response."""
            return self.json_data

    # return the URL to check whether we are calling the correct service.
    resp = {
        "requestId": "f98d1366-738e-4c14-a3ff-594f359e131c",
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

    resp_true = {"status": "Successful"}
    resp_false = {"status": "Unknown"}

    if flag == "false":
        return MockResponse(resp, 400)
    elif flag == "true":
        return MockResponse(resp, 200)
    elif flag == "lic_true":
        return MockResponse(resp_true, 200)
    elif flag == "lic_false":
        return MockResponse(resp_false, 200)


def test_select_latest_version():
    """Test the function select_latest_version."""
    lat_ver = select_latest_version("-1", ["3.4.5", "3.4.1"], "pkg")
    assert lat_ver == "3.4.5"

    lat_ver = select_latest_version("-1", ["3.4.1", "3.4.5"], "pkg")
    assert lat_ver == "3.4.5"

    lat_ver = select_latest_version("3.4.5", ["3.4.1", "3.4.0"], "pkg")
    assert lat_ver == "3.4.5"

    lat_ver = select_latest_version("-1", ["-1", "-1"], "pkg")
    assert lat_ver == ''

    lat_ver = select_latest_version(["abc"], [{"a": "b"}, ["b"]], "pkg")
    assert lat_ver == ''


if __name__ == '__main__':
    test_execute_gremlin_dsl()
    test_select_latest_version()
    test_check_license_conflict()
    test_execute_gremlin_dsl2()
