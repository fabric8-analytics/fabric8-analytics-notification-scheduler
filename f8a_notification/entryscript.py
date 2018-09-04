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
    get_repos()
    get_version_data(PACKAGE_DATA, NEW_VERSION_DATA, VERSION_DATA)
    get_version_data(TRANSITIVE_PACKAGE_DATA, NEW_TRANSITIVE_VERSION_DATA,
                     TRANSITIVE_VERSION_DATA, "true")
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
        eco = get_value(result, 'ecosystem')
        name = get_value(result, 'name')
        if not eco + ":" + name in PACKAGE_DATA:
            PACKAGE_DATA[eco + ":" + name] = {}
        tmp_json['name'] = name
        tmp_json['ecosystem'] = eco
        tmp_json['versions'] = []
        PACKAGE_DATA[eco + ":" + name] = tmp_json
    print("read_packages() ended")


def get_version_data(pkg_data, new_ver_data, version_data, tr_flag="false"):
    """Get all the version info for the packages."""
    print("get_version_data() started")
    pkg_list = []
    eco_lst = []
    license_lst = []

    for repo in REPO_DATA:

        if tr_flag is "true" and "tr_dependencies" in REPO_DATA[repo]:
            deps = REPO_DATA[repo]['tr_dependencies']
        elif tr_flag is "false":
            deps = REPO_DATA[repo]['dependencies']
        else:
            continue

        for dep in deps:
            dep_data = version_data[dep]
            pkg_list.append(dep_data['name'])
            eco_lst.append(REPO_DATA[repo]['ecosystem'])

    query_str = "g.V().has('pecosystem',within(eco_lst))." \
                "has('pname',within(pkg_list))" \
                ".hasNot('cve_ids').valueMap().dedup()"
    payload = {
        'gremlin': query_str,
        'bindings': {
            'pkg_list': list(set(pkg_list)),
            'eco_lst': list(set(eco_lst))
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
        pkg_key = eco + ":" + name

        del license_lst[:]
        if 'licenses' in result:
            for lic in result['licenses']:
                license_lst.append(lic)
            key = eco + ":" + name + ":" + ver
            new_ver_data[key] = {}
            new_ver_data[key]['version'] = ver
            new_ver_data[key]['package'] = eco + ":" + name
            new_ver_data[key]['license'] = license_lst
        if pkg_key not in pkg_data:
            pkg_data[pkg_key] = {}
            pkg_data[pkg_key]['name'] = name
            pkg_data[pkg_key]['ecosystem'] = eco
            pkg_data[pkg_key]['versions'] = []
        pkg_data[pkg_key]['versions'].append(key)
    print("get_version_data() ended")


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
            VERSION_DATA[key]['name'] = name
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
        TRANSITIVE_VERSION_DATA[key]['name'] = name
        TRANSITIVE_VERSION_DATA[key]['package'] = eco + ":" + name

        pkg_key = eco + ":" + name
        TRANSITIVE_PACKAGE_DATA[pkg_key] = {}
        TRANSITIVE_PACKAGE_DATA[pkg_key]['ecosystem'] = eco
        TRANSITIVE_PACKAGE_DATA[pkg_key]['name'] = name
        TRANSITIVE_PACKAGE_DATA[pkg_key]['versions'] = []

        if repo not in REPO_DATA:
            REPO_DATA[repo] = {}
        REPO_DATA[repo]['ecosystem'] = eco
        if 'tr_dependencies' not in REPO_DATA[repo]:
            REPO_DATA[repo]['tr_dependencies'] = []
        key = eco + ":" + name + ":" + version
        if key not in REPO_DATA[repo]['tr_dependencies']:
            REPO_DATA[repo]['tr_dependencies'].append(key)
    print("get_repos() ended")


def find_latest_version(pkg_data,
                        version_data,
                        new_version_data,
                        transitive_flag="false"):
    """Find the latest version."""
    print("find_latest_version() started")
    tr_lst = []
    dir_lst = []

    for repo in REPO_DATA:
        del tr_lst[:]
        del dir_lst[:]
        if transitive_flag is "false":
            deps = REPO_DATA[repo]['dependencies']
            FINAL_DATA[repo] = {}
            FINAL_DATA[repo]['notify'] = "false"
            FINAL_DATA[repo]['transitive_updates'] = []
            FINAL_DATA[repo]['direct_updates'] = []

        else:
            if 'tr_dependencies' in REPO_DATA[repo]:
                deps = REPO_DATA[repo]['tr_dependencies']
            else:
                deps = []
        for dep in deps:
            tmp_json = {}
            ver_lst = []
            pkg = version_data[dep]['package']
            if pkg in pkg_data and \
                    (dep in new_version_data or dep in version_data) and \
                    (transitive_flag is "false" or (
                            FINAL_DATA[repo]['notify'] is "true" and transitive_flag is "true")):
                if 'versions' in pkg_data[pkg]:
                    versions = pkg_data[pkg]['versions']
                    for ver in versions:
                        ver_lst.append(new_version_data[ver]['version'])
                cur_ver = version_data[dep]['version']
                pkg_name = pkg_data[pkg]['name']
                latest_version = \
                    select_latest_version(cur_ver,
                                          ver_lst,
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
                        tr_lst.append(tmp_json)
                    else:
                        dir_lst.append(tmp_json)
        if tr_lst:
            FINAL_DATA[repo]['transitive_updates'].extend(tr_lst[:])
        if dir_lst:
            FINAL_DATA[repo]['direct_updates'].extend(dir_lst[:])

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
            ver_updates = FINAL_DATA[repo]['direct_updates']
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
                                    "transitive_updates": [],
                                    "direct_updates": []
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
            tmp_json['data']['attributes']['custom']['transitive_updates'] \
                = repo_data['transitive_updates']
            tmp_json['data']['attributes']['custom']['direct_updates'] \
                = repo_data['direct_updates']
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
