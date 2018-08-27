# -*- coding: utf-8 -*-

# Copyright © 2018 Red Hat Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Author: Yusuf Zainee <yzainee@redhat.com>
#         Geetika Batra <gbatra@redhat.com>
#

"""Class to create cron script."""


import json
import logging
import sys

from pprint import pprint
from datetime import datetime, timedelta
from utils import select_latest_version, execute_gremlin_dsl
from utils import get_response_data, check_license_conflict
from user_notification import UserNotification as un
from auth import Authentication
from uuid import uuid4


PACKAGE_DATA = {}
REPO_DATA = {}
NEW_VERSION_DATA = {}
VERSION_DATA = {}
FINAL_DATA = {}
TRANSITIVE_PACKAGE_DATA = {}
TRANSITIVE_VERSION_DATA = {}
NEW_TRANSITIVE_VERSION_DATA = {}

logger = logging.getLogger(__name__)


def get_value(json, property):
    """Get the values from json."""
    return json.get(property, [''])[0]


def run():
    """Entrypoint function."""
    logger.info("Scheduled scan for newer versions started")
    print("Scheduled scan for newer versions started")
    read_packages()
    remove_cve_versions(PACKAGE_DATA, NEW_VERSION_DATA)
    get_repos()
    get_transitive_package_data()
    remove_cve_versions(TRANSITIVE_PACKAGE_DATA, NEW_TRANSITIVE_VERSION_DATA)
    find_latest_version(PACKAGE_DATA,
                        VERSION_DATA,
                        NEW_VERSION_DATA, "false")
    check_license_compatibility()
    find_latest_version(TRANSITIVE_PACKAGE_DATA,
                        TRANSITIVE_VERSION_DATA,
                        NEW_TRANSITIVE_VERSION_DATA, "true")
    generate_notification_payload()
    logger.info("Scheduled scan for newer versions finished")
    print("Scheduled scan for newer versions finished")


def read_packages():
    """Read all the packages last updated."""
    print("read_packages() started")
    prev_date = (datetime.utcnow() - timedelta(1)).strftime('%Y%m%d')
    query_str = "g.V().has('latest_version_last_updated',prev_date).valueMap()"
    # prev_date = '20180824'  # for testing purpose, change date here
    payload = {
        'gremlin': query_str,
        'bindings': {
            'prev_date': prev_date
        }
    }
    gremlin_response = execute_gremlin_dsl(payload)
    if gremlin_response is not None:
        result_data = get_response_data(gremlin_response, [{0: 0}])
    else:
        print("Exception occured while trying to fetch packages : read_package")
        sys.exit()

    for result in result_data:
        tmp_json = {}
        tmp_json['latest'] = get_value(result, 'latest_version')
        tmp_json['libio'] = get_value(result, 'libio_latest_version')
        eco = get_value(result, 'ecosystem')
        name = get_value(result, 'name')
        if not eco + ":" + name in PACKAGE_DATA:
            PACKAGE_DATA[eco + ":" + name] = {}
        tmp_json['name'] = name
        tmp_json['ecosystem'] = eco
        PACKAGE_DATA[eco + ":" + name] = tmp_json
    print("read_packages() ended")


def remove_cve_versions(pkg_data, new_ver_data):
    """Remove CVE versions."""
    print("remove_cve_versions() started")
    pkg_list = []
    ver_list = []
    eco_lst = []
    license_lst = []
    for pkg in pkg_data:
        if not pkg_data[pkg]['name'] in pkg_list:
            pkg_list.append(pkg_data[pkg]['name'])
        if not pkg_data[pkg]['latest'] in ver_list:
            ver_list.append(pkg_data[pkg]['latest'])
        if not pkg_data[pkg]['libio'] in ver_list:
            ver_list.append(pkg_data[pkg]['libio'])
        if not pkg_data[pkg]['ecosystem'] in eco_lst:
            eco_lst.append(pkg_data[pkg]['ecosystem'])

    query_str = "g.V().has('pecosystem',within(eco_lst))." \
                "has('pname',within(pkg_list))" \
                ".has('version',within(ver_list)).valueMap()"
    payload = {
        'gremlin': query_str,
        'bindings': {
            'pkg_list': pkg_list,
            'ver_list': ver_list,
            'eco_lst': eco_lst
        }
    }

    gremlin_response = execute_gremlin_dsl(payload)
    if gremlin_response is not None:
        result_data = get_response_data(gremlin_response, [{0: 0}])
    else:
        print("Exception occured while trying to fetch versions : remove_cve_versions")
        sys.exit()

    for result in result_data:
        name = get_value(result, 'pname')
        eco = get_value(result, 'pecosystem')
        ver = get_value(result, 'version')
        if 'cve_ids' in result:
            if pkg_data[eco + ":" + name]['latest'] == ver:
                del pkg_data[eco + ":" + name]['latest']
            elif pkg_data[eco + ":" + name]['libio'] == ver:
                del pkg_data[eco + ":" + name]['libio']
            if 'libio' not in pkg_data[eco + ":" + name] \
                    and 'latest' not in pkg_data[eco + ":" + name]:
                del pkg_data[eco + ":" + name]
        else:
            del license_lst[:]
            if 'licenses' in result:
                for lic in result['licenses']:
                    license_lst.append(lic)
                key = eco + ":" + name + ":" + ver
                new_ver_data[key] = {}
                new_ver_data[key]['version'] = ver
                new_ver_data[key]['package'] = eco + ":" + name
                new_ver_data[key]['license'] = license_lst
    print("remove_cve_versions() ended")


def get_repos():
    """Read all the repo data."""
    print("get_repos() started")
    pkg_list = []
    license_lst = []
    eco_lst = []
    for pkg in PACKAGE_DATA:
        pkg_list.append(PACKAGE_DATA[pkg]['name'])
        eco_lst.append(PACKAGE_DATA[pkg]['ecosystem'])

    query_str = "g.V().has('pecosystem',within(eco_lst))." \
                "has('pname',within(pkg_list))" \
                ".in('has_dependency').valueMap()"
    payload = {
        'gremlin': query_str,
        'bindings': {
            'pkg_list': pkg_list,
            'eco_lst': eco_lst
        }
    }
    gremlin_response = execute_gremlin_dsl(payload)
    if gremlin_response is not None:
        result_data = get_response_data(gremlin_response, [{0: 0}])
    else:
        print("Exception occured while trying to fetch repo : get_repos")
        sys.exit()
    repo_list = []
    for data in result_data:
        repo_list.append(get_value(data, 'repo_url'))

    query_str = "g.V().has('repo_url', within(repo_list)).as('a')." \
                "out('has_dependency').as('b').select('a','b').by(valueMap())"
    payload = {
        'gremlin': query_str,
        'bindings': {
            'repo_list': repo_list
        }
    }
    gremlin_response = execute_gremlin_dsl(payload)
    if gremlin_response is not None:
        result_data = get_response_data(gremlin_response, [{0: 0}])
    else:
        print("Exception occured while trying to fetch versions : get_repos")
        sys.exit()

    for result in result_data:
        repo = get_value(result['a'], 'repo_url')
        del license_lst[:]
        if 'licenses' in result['b']:
            licenses = result['b']['licenses']
            for lic in licenses:
                license_lst.append(lic)
            eco = get_value(result['b'], 'pecosystem')
            name = get_value(result['b'], 'pname')
            version = get_value(result['b'], 'version')
            key = eco + ":" + name + ":" + version
            VERSION_DATA[key] = {}
            VERSION_DATA[key]['version'] = version
            VERSION_DATA[key]['package'] = eco + ":" + name
            VERSION_DATA[key]['license'] = license_lst
        if repo not in REPO_DATA:
            REPO_DATA[repo] = {}
        REPO_DATA[repo]['ecosystem'] = eco
        if 'dependencies' not in REPO_DATA[repo]:
            REPO_DATA[repo]['dependencies'] = []
        key = eco + ":" + name + ":" + version
        if key not in REPO_DATA[repo]['dependencies']:
            REPO_DATA[repo]['dependencies'].append(key)

    query_str = "g.V().has('repo_url', within(repo_list)).as('a')." \
                "out('has_transitive_dependency').as('b').select('a','b').by(valueMap())"
    payload = {
        'gremlin': query_str,
        'bindings': {
            'repo_list': repo_list
        }
    }
    gremlin_response = execute_gremlin_dsl(payload)
    if gremlin_response is not None:
        result_data = get_response_data(gremlin_response, [{0: 0}])
    else:
        print("Exception occured while trying to fetch versions : get_repos")
        sys.exit()

    for result in result_data:
        repo = get_value(result['a'], 'repo_url')
        eco = get_value(result['b'], 'pecosystem')
        name = get_value(result['b'], 'pname')
        version = get_value(result['b'], 'version')
        key = eco + ":" + name + ":" + version
        TRANSITIVE_VERSION_DATA[key] = {}
        TRANSITIVE_VERSION_DATA[key]['version'] = version
        TRANSITIVE_VERSION_DATA[key]['package'] = eco + ":" + name

        pkg_key = eco + ":" + name
        TRANSITIVE_PACKAGE_DATA[pkg_key] = {}
        TRANSITIVE_PACKAGE_DATA[pkg_key]['ecosystem'] = eco
        TRANSITIVE_PACKAGE_DATA[pkg_key]['name'] = name

        if repo not in REPO_DATA:
            REPO_DATA[repo] = {}
        REPO_DATA[repo]['ecosystem'] = eco
        if 'tr_dependencies' not in REPO_DATA[repo]:
            REPO_DATA[repo]['tr_dependencies'] = []
        key = eco + ":" + name + ":" + version
        if key not in REPO_DATA[repo]['tr_dependencies']:
            REPO_DATA[repo]['tr_dependencies'].append(key)
    print("get_repos() ended")


def get_transitive_package_data():
    """Find the transitive package details."""
    print("get_transitive_package_data() started")
    pkg_list = []
    eco_lst = []
    for pkg in TRANSITIVE_PACKAGE_DATA:
        pkg_list.append(TRANSITIVE_PACKAGE_DATA[pkg]['name'])
        eco_lst.append(TRANSITIVE_PACKAGE_DATA[pkg]['ecosystem'])
    query_str = "g.V().has('ecosystem',within(eco_lst))." \
                "has('name', within(pkg_list)).valueMap()"
    payload = {
        'gremlin': query_str,
        'bindings': {
            'pkg_list': pkg_list,
            'eco_lst': eco_lst
        }
    }
    gremlin_response = execute_gremlin_dsl(payload)
    if gremlin_response is not None:
        result_data = get_response_data(gremlin_response, [{0: 0}])
    else:
        print("Exception occured while trying to fetch versions : remove_cve_versions")
        sys.exit()
    for result in result_data:
        tmp_json = {}
        tmp_json['latest'] = get_value(result, 'latest_version')
        tmp_json['libio'] = get_value(result, 'libio_latest_version')
        eco = get_value(result, 'ecosystem')
        name = get_value(result, 'name')
        if not eco + ":" + name in PACKAGE_DATA:
            TRANSITIVE_PACKAGE_DATA[eco + ":" + name] = {}
        tmp_json['name'] = name
        tmp_json['ecosystem'] = eco
        TRANSITIVE_PACKAGE_DATA[eco + ":" + name] = tmp_json
    print("get_transitive_package_data() ended")


def find_latest_version(pkg_data,
                        version_data,
                        new_version_data,
                        transitive_flag="false"):
    """Find the latest version."""
    print("find_latest_version() started")
    tmp_lst = []
    for repo in REPO_DATA:
        del tmp_lst[:]
        latest_ver = ''
        libio_ver = ''
        if transitive_flag is "false":
            deps = REPO_DATA[repo]['dependencies']
            FINAL_DATA[repo] = {}
            FINAL_DATA[repo]['notify'] = "false"
        else:
            if 'tr_dependencies' in REPO_DATA[repo]:
                deps = REPO_DATA[repo]['tr_dependencies']
            else:
                deps = []
        for dep in deps:
            print(dep)
            tmp_json = {}
            pkg = version_data[dep]['package']
            if pkg in pkg_data and \
                    (dep in new_version_data or dep in version_data) and \
                    (transitive_flag is "false" or (
                            FINAL_DATA[repo]['notify'] is "true" and transitive_flag is "true")):
                if 'latest' in pkg_data[pkg]:
                    latest_ver = pkg_data[pkg]['latest']
                if 'libio' in pkg_data[pkg]:
                    libio_ver = pkg_data[pkg]['libio']
                cur_ver = version_data[dep]['version']
                pkg_name = pkg_data[pkg]['name']
                latest_version = \
                    select_latest_version(cur_ver,
                                          libio_ver,
                                          latest_ver,
                                          pkg_name)
                eco = REPO_DATA[repo]['ecosystem']
                latest_key = eco + ":" + pkg_name + ":" + latest_version
                if latest_version != cur_ver and \
                        (latest_key in new_version_data or latest_key in version_data):
                    FINAL_DATA[repo]['notify'] = "true"
                    tmp_json['ecosystem'] = eco
                    tmp_json['name'] = pkg_name
                    tmp_json['version'] = cur_ver
                    tmp_json['latest_version'] = latest_version
                    if transitive_flag is "true":
                        tmp_json['is_transitive'] = "true"
                    tmp_lst.append(tmp_json)
        if tmp_lst:
            if 'version_updates' not in FINAL_DATA[repo]:
                FINAL_DATA[repo]['version_updates'] = []
            FINAL_DATA[repo]['version_updates'].extend(tmp_lst[:])

    print("find_latest_version() ended")


def check_license_compatibility():
    """Check the license compatibility."""
    print("check_license_compatibility() started")
    for repo in REPO_DATA:
        lic_json = {}
        if FINAL_DATA[repo]['notify'] == 'true':
            lic_json['packages'] = []
            deps = REPO_DATA[repo]['dependencies']
            for dep in deps:
                tmp_json = {}
                tmp_json['package'] = VERSION_DATA[dep]['package']
                tmp_json['version'] = VERSION_DATA[dep]['version']
                tmp_json['licenses'] = VERSION_DATA[dep]['license'][:]
                lic_json['packages'].append(tmp_json)
            ver_updates = FINAL_DATA[repo]['version_updates']
            for ver in ver_updates:
                tmp_json = {}
                eco = ver['ecosystem']
                tmp_json['package'] = ver['name']
                tmp_json['version'] = ver['latest_version']
                key = eco + ":" + ver['name'] + ":" + ver['latest_version']
                tmp_json['licenses'] = NEW_VERSION_DATA[key]['license'][:]
                lic_json['packages'].append(tmp_json)

            print(lic_json)
            is_conflict = check_license_conflict(lic_json)
            print("License Conflict Result: ", is_conflict)
            if is_conflict == "true":
                FINAL_DATA[repo]['notify'] = 'false'
    print("check_license_compatibility() ended")


def generate_notification_payload():
    """Generate the final payload."""
    print("generate_notification_payload() started")
    final_payload = []
    for data in FINAL_DATA:
        repo_data = FINAL_DATA[data]
        if repo_data['notify'] == 'true':
            tmp_json = {"data": {
                            "attributes": {
                                "custom": {
                                    "repo_url": "",
                                    "scanned_at": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                                    "version_updates": []
                                },
                                "id": "",
                                "type": "analytics.notify.version"
                            },

                            "id": str(uuid4()),
                            "type": "notifications"
                        }
                        }
            tmp_json['data']['attributes']['custom']['repo_url'] = data
            tmp_json['data']['attributes']['id'] = data
            tmp_json['data']['attributes']['custom']['version_updates'] \
                = repo_data['version_updates']
            final_payload.append(tmp_json)
    print("<---Repo Data--->")
    print(REPO_DATA)
    print("<---Package Data--->")
    print(PACKAGE_DATA)
    print("<---New Version Data--->")
    print(NEW_VERSION_DATA)
    print("<---Version Data--->")
    print(VERSION_DATA)
    print("<---Transitive Package Data--->")
    print(TRANSITIVE_PACKAGE_DATA)
    print("<---Transitive Version Data--->")
    print(TRANSITIVE_VERSION_DATA)
    print("<---New Transitive Version Data--->")
    print(NEW_TRANSITIVE_VERSION_DATA)
    print("<---Final Data--->")
    print(FINAL_DATA)
    print("<-------------Payload for Notification------------->")
    print(final_payload)
    try:
        auth_ = Authentication.init_auth_sa_token()
        print("<------------AUTH------------->")
        print(auth_)
        if auth_ is not None:
            notify_ = un.send_notification(final_payload, auth_)
            print("<------------NOTIFY------------>")
            print(notify_)
    except Exception as e:
        logger.info(str(e))
        print(str(e))
        sys.exit()
    print("generate_notification_payload() ended")


if __name__ == "__main__":
    run()
