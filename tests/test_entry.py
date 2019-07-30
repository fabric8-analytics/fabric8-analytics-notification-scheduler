
"""Test module for classes and functions found in the entryscript module."""
import entryscript as es
from unittest import mock


def mock_repo_response():
    """Generate data for repo response."""
    x = {
        "result": {
            "data": [
                {
                    "repo_url": ["xyz/xyz"]
                }
            ]
        }

    }
    return x


def mock_repo_combo_response():
    """Generate data for direct deps response."""
    x = {
        "result": {
            "data": [
                {
                    "a": {
                        "repo_url": ["xyz/xyz"]
                    },
                    "b": {
                        "pecosystem": ["maven"],
                        "pname": ["io.vertx:vertx-web"],
                        "version": ["3.4.1"],
                        "licenses": ["a", "b"]
                    }
                }

            ]
        }

    }
    return x


def mock_repo_tr_response():
    """Generate data for transitive repo deps response."""
    x = {
        "result": {
            "data": [
                {
                    "a": {
                        "repo_url": ["xyz/xyz"]
                    },
                    "b": {
                        "pecosystem": ["maven"],
                        "pname": ["io.vertx:vertx-core"],
                        "version": ["3.4.1"],
                        "licenses": ["a", "b"]
                    }
                }

            ]
        }

    }
    return x


def mock_response():
    """Generate data for mock response."""
    x = {
        "result": {
            "data": [
                {
                    "ecosystem": ["maven"],
                    "name": ["io.vertx:vertx-web"]
                }
            ]
        }

    }
    return x


def mock_ver_response():
    """Generate data for version response."""
    x = {
        "result": {
            "data": [
                {
                    "pecosystem": ["maven"],
                    "pname": ["io.vertx:vertx-web"],
                    "version": ["3.4.1"],
                    "licenses": ["a", "b"]
                }
            ]
        }

    }
    return x


@mock.patch("entryscript.execute_gremlin_dsl")
def test_read_packages(mocker):
    """Test read_packages function."""
    mocker.return_value = mock_response()
    es.read_packages()
    assert "maven:io.vertx:vertx-web" in es.PACKAGE_DATA


@mock.patch("entryscript.execute_gremlin_dsl")
def test_get_version_data(mocker):
    """Test get_version_data function."""
    repo_data = {
        "xyz/xyz": {
            "ecosystem": "maven",
            "dependencies": ["maven:io.vertx:vertx-web:3.4.1"],
            "tr_dependencies": ["maven:io.vertx:vertx-web:3.4.2"]
        },
        "abc/abc": {
            "ecosystem": "maven",
            "dependencies": ["maven:io.vertx:vertx-web:3.4.1"]
        }
    }
    mocker.return_value = mock_ver_response()
    pkg_data = {}
    new_ver_data = {}

    version_data = {
        "maven:io.vertx:vertx-web:3.4.1": {
            "ecosystem": "maven",
            "name": "io.vertx:vertx-web"
        },
        "maven:io.vertx:vertx-web:3.4.2": {
            "ecosystem": "maven",
            "name": "io.vertx:vertx-web"
        }
    }
    es.get_version_data(repo_data, pkg_data, new_ver_data, version_data)
    assert "maven:io.vertx:vertx-web" in es.PACKAGE_DATA
    assert "maven:io.vertx:vertx-web:3.4.1" in new_ver_data

    pkg_data = {}
    new_ver_data = {}

    mocker.return_value = mock_ver_response()
    es.get_version_data(repo_data, pkg_data, new_ver_data, version_data, "true")
    assert "maven:io.vertx:vertx-web" in es.PACKAGE_DATA
    assert "maven:io.vertx:vertx-web:3.4.1" in new_ver_data


@mock.patch("entryscript.execute_gremlin_dsl")
def test_get_repos(mocker):
    """Test get_repos function."""
    mocker.side_effect = [mock_repo_response(),
                          mock_repo_combo_response(),
                          mock_repo_tr_response()]
    es.get_repos()
    assert "maven:io.vertx:vertx-web:3.4.1" in es.VERSION_DATA
    assert "maven:io.vertx:vertx-core:3.4.1" in es.TRANSITIVE_VERSION_DATA


def test_find_latest_version():
    """Test find_latest_version function."""
    es.REPO_DATA = {
        "xyz/xyz": {
            "ecosystem": "maven",
            "dependencies": ["maven:io.vertx:vertx-web:3.4.1"],
            "tr_dependencies": ["maven:io.vertx:vertx-core:3.4.1"]
        }
    }
    new_version = {
        "maven:io.vertx:vertx-web:3.4.1": {
            "package": "maven:io.vertx:vertx-web",
            "version": "3.4.1"
        },
        "maven:io.vertx:vertx-core:3.4.1": {
            "package": "maven:io.vertx:vertx-core",
            "version": "3.4.1"
        },
        "maven:io.vertx:vertx-web:3.4.2": {
            "package": "maven:io.vertx:vertx-web",
            "version": "3.4.2"
        },
        "maven:io.vertx:vertx-core:3.4.2": {
            "package": "maven:io.vertx:vertx-core",
            "version": "3.4.2"
        }
    }
    version_data = {
        "maven:io.vertx:vertx-web:3.4.1": {
            "package": "maven:io.vertx:vertx-web",
            "version": "3.4.1"
        },
        "maven:io.vertx:vertx-core:3.4.1": {
            "package": "maven:io.vertx:vertx-core",
            "version": "3.4.1"
        }
    }
    pkg_data = {
        "maven:io.vertx:vertx-web": {
            "versions": ["maven:io.vertx:vertx-web:3.4.1", "maven:io.vertx:vertx-web:3.4.2"],
            "name": "io.vertx:vertx-web"
        },
        "maven:io.vertx:vertx-core": {
            "versions": ["maven:io.vertx:vertx-core:3.4.1", "maven:io.vertx:vertx-core:3.4.2"],
            "name": "io.vertx:vertx-core"
        }
    }
    es.find_latest_version(pkg_data, version_data, new_version)
    assert "io.vertx:vertx-web" == es.FINAL_DATA['xyz/xyz']['direct_updates'][0]['name']

    es.find_latest_version(pkg_data, version_data, new_version, "true")
    assert "io.vertx:vertx-core" == es.FINAL_DATA['xyz/xyz']['transitive_updates'][0]['name']


@mock.patch("entryscript.check_license_conflict")
def test_check_license_compatibility(mocker):
    """Test check_license_compatibility function."""
    es.REPO_DATA = {
        "xyz/xyz": {
            "ecosystem": "maven",
            "dependencies": ["maven:io.vertx:vertx-web:3.4.1"],
            "tr_dependencies": ["maven:io.vertx:vertx-core:3.4.1"]
        }
    }

    es.FINAL_DATA = {
        "xyz/xyz": {
            "notify": "true",
            "direct_updates": [{
                "ecosystem": "maven",
                "name": "io.vertx:vertx-web",
                "latest_version": "3.4.2"
            }
                               ]
        }
    }

    es.NEW_VERSION_DATA = {
        "maven:io.vertx:vertx-web:3.4.2": {
            "package": "maven:io.vertx:vertx-web",
            "version": "3.4.2",
            "license": ["a"]
        }
    }

    es.VERSION_DATA = {
        "maven:io.vertx:vertx-web:3.4.1": {
            "package": "maven:io.vertx:vertx-web",
            "version": "3.4.1",
            "license": ["a", "b"]
        },
        "maven:io.vertx:vertx-core:3.4.1": {
            "package": "maven:io.vertx:vertx-core",
            "version": "3.4.1"
        }
    }

    mocker.return_value = "false"
    es.check_license_compatibility()
    assert es.FINAL_DATA['xyz/xyz']['notify'] == "true"
    assert es.FINAL_DATA['xyz/xyz']['direct_updates'][0]['name'] == "io.vertx:vertx-web"

    mocker.return_value = "true"
    es.check_license_compatibility()
    assert es.FINAL_DATA['xyz/xyz']['notify'] == "false"


@mock.patch("entryscript.Authentication.init_auth_sa_token")
@mock.patch("entryscript.un.send_notification")
def test_generate_notification_payload(mocker, mocker2):
    """Test generate_notification_payload function."""
    es.FINAL_DATA = {
        "xyz/xyz": {
            "notify": "true",
            "direct_updates": [{
                "ecosystem": "maven",
                "name": "io.vertx:vertx-web",
                "latest_version": "3.4.2"
            }
            ],
            "transitive_updates": [{
                "ecosystem": "maven",
                "name": "io.vertx:vertx-core",
                "latest_version": "3.4.2"
            }
            ]
        }
    }
    mocker.return_value = "abcd"
    mocker2.return_value = "defg"
    out = es.generate_notification_payload()
    assert out == "success"


@mock.patch("entryscript.read_packages")
@mock.patch("entryscript.get_repos")
@mock.patch("entryscript.get_version_data")
@mock.patch("entryscript.find_latest_version")
@mock.patch("entryscript.check_license_compatibility")
@mock.patch("entryscript.generate_notification_payload")
def test_run(m1, m2, m3, m4, m5, m6):
    """Test run function."""
    m1.return_value = "success"
    m2.return_value = ""
    m3.return_value = ""
    m4.return_value = ""
    m5.return_value = ""
    m6.return_value = ""
    out = es.run()
    assert out == "success"


if __name__ == '__main__':
    test_read_packages()
    test_get_version_data()
    test_get_repos()
    test_find_latest_version()
    test_check_license_compatibility()
    test_generate_notification_payload()
    test_run()
