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
#

"""Class to create cron script."""


import json
from pprint import pprint
from datetime import datetime, timedelta
from utils import select_latest_version, execute_gremlin_dsl, get_response_data, check_license_conflict
from uuid import uuid4
import logging

PACKAGE_DATA = {}
REPO_DATA = {}
NEW_VERSION_DATA = {}
VERSION_DATA = {}
FINAL_DATA = {}

logger = logging.getLogger(__name__)


def run():
    logger.info("Scheduled scan for newer versions started")
    read_packages()
    remove_cve_versions()
    get_repos()
    find_latest_version()
    check_license_compatibility()
    generate_notification_payload()
    logger.info("Scheduled scan for newer versions finished")


def read_packages():
    prev_date = (datetime.utcnow() - timedelta(1)).strftime('%Y%m%d')
    query_str = "g.V().has('vertex_label','Package').has('latest_version_last_updated',prev_date)"
    prev_date = '20180805'
    payload = {
        'gremlin': query_str,
        'bindings': {
            'prev_date': prev_date
        }
    }
    gremlin_response = execute_gremlin_dsl(payload)
    result_data = get_response_data(gremlin_response, [{0: 0}])

    tmp_json = {}
    for result in result_data:
        tmp_json.clear()
        tmp_json['latest'] = result['properties']['latest_version'][0]['value']
        tmp_json['libio'] = result['properties']['libio_latest_version'][0]['value']
        eco = result['properties']['ecosystem'][0]['value']
        name = result['properties']['name'][0]['value']
        if not eco + ":" + name in PACKAGE_DATA:
            PACKAGE_DATA[eco + ":" + name] = {}
        tmp_json['name'] = name
        tmp_json['ecosystem'] = eco
        PACKAGE_DATA[eco + ":" + name] = tmp_json


def remove_cve_versions():
    pkg_list = []
    ver_list = []
    eco_lst = []
    license_lst = []
    for pkg in PACKAGE_DATA:
        pkg_list.append(PACKAGE_DATA[pkg]['name'])
        ver_list.append(PACKAGE_DATA[pkg]['latest'])
        ver_list.append(PACKAGE_DATA[pkg]['libio'])
        eco_lst.append(PACKAGE_DATA[pkg]['ecosystem'])

    query_str = "g.V().has('vertex_label','Version').has('pecosystem',within(eco_lst)).has('pname',within(pkg_list)).has('version',within(ver_list))"
    payload = {
        'gremlin': query_str,
        'bindings': {
            'pkg_list': pkg_list,
            'ver_list': ver_list,
            'eco_lst': eco_lst
        }
    }
    gremlin_response = execute_gremlin_dsl(payload)
    result_data = get_response_data(gremlin_response, [{0: 0}])

    for result in result_data:
        name = result['properties']['pname'][0]['value']
        eco = result['properties']['pecosystem'][0]['value']
        if 'cve_ids' in result['properties']:
            ver = result['properties']['version'][0]['value']
            if PACKAGE_DATA[eco + ":" + name]['latest'] == ver:
                del PACKAGE_DATA[eco + ":" + name]['latest']
            elif PACKAGE_DATA[eco + ":" + name]['libio'] == ver:
                del PACKAGE_DATA[eco + ":" + name]['libio']
            if 'libio' not in PACKAGE_DATA[eco + ":" + name] and 'latest' not in PACKAGE_DATA[eco + ":" + name]:
                del PACKAGE_DATA[eco + ":" + name]
        else:
            del license_lst[:]
            for lic in result['properties']['licenses']:
                license_lst.append(lic['value'])
            ver = result['properties']['version'][0]['value']
            key = eco + ":" + name + ":" + ver
            NEW_VERSION_DATA[key] = {}
            NEW_VERSION_DATA[key]['version'] = ver
            NEW_VERSION_DATA[key]['package'] = eco + ":" + name
            NEW_VERSION_DATA[key]['license'] = license_lst


def get_repos():
    pkg_list = []
    license_lst = []
    eco_lst = []
    for pkg in PACKAGE_DATA:
        pkg_list.append(PACKAGE_DATA[pkg]['name'])
        eco_lst.append(PACKAGE_DATA[pkg]['ecosystem'])

    query_str = "g.V().has('vertex_label','Version').has('pecosystem',within(eco_lst)).has('pname',within(pkg_list)).in('has_dependency')"
    payload = {
        'gremlin': query_str,
        'bindings': {
            'pkg_list': pkg_list,
            'eco_lst': eco_lst
        }
    }
    gremlin_response = execute_gremlin_dsl(payload)
    result_data = get_response_data(gremlin_response, [{0: 0}])
    repo_list = []
    for data in result_data:
        repo_list.append(data['properties']['repo_url'][0]['value'])

    query_str = "g.V().has('vertex_label','Repo').has('repo_url', within(repo_list)).as('a').out('has_dependency').as('b').select('a','b')"
    payload = {
        'gremlin': query_str,
        'bindings': {
            'repo_list': repo_list
        }
    }
    gremlin_response = execute_gremlin_dsl(payload)
    result_data = get_response_data(gremlin_response, [{0: 0}])

    for result in result_data:
        repo = result['a']['properties']['repo_url'][0]['value']
        del license_lst[:]
        for lic in result['b']['properties']['licenses']:
            license_lst.append(lic['value'])
        eco = result['b']['properties']['pecosystem'][0]['value']
        name = result['b']['properties']['pname'][0]['value']
        version = result['b']['properties']['version'][0]['value']
        VERSION_DATA[eco + ":" + name + ":" + version] = {}
        VERSION_DATA[eco + ":" + name + ":" + version]['version'] = version
        VERSION_DATA[eco + ":" + name + ":" + version]['package'] = eco + ":" + name
        VERSION_DATA[eco + ":" + name + ":" + version]['license'] = license_lst
        if repo not in REPO_DATA:
            REPO_DATA[repo] = {}
        REPO_DATA[repo]['ecosystem'] = eco
        if 'dependencies' not in REPO_DATA[repo]:
            REPO_DATA[repo]['dependencies'] = []
        if not eco + ":" + name + ":" + version in REPO_DATA[repo]['dependencies']:
            REPO_DATA[repo]['dependencies'].append(eco + ":" + name + ":" + version)


def find_latest_version():
    tmp_lst = []
    for repo in REPO_DATA:
        del tmp_lst[:]
        FINAL_DATA[repo] = {}
        FINAL_DATA[repo]['notify'] = "false"
        latest_ver = ''
        libio_ver = ''
        deps = REPO_DATA[repo]['dependencies']
        for dep in deps:
            tmp_json = {}
            pkg = VERSION_DATA[dep]['package']
            if pkg in PACKAGE_DATA and (dep in NEW_VERSION_DATA or dep in VERSION_DATA):
                if 'latest' in PACKAGE_DATA[pkg]:
                    latest_ver = PACKAGE_DATA[pkg]['latest']
                if 'libio' in PACKAGE_DATA[pkg]:
                    libio_ver = PACKAGE_DATA[pkg]['libio']
                cur_ver = VERSION_DATA[dep]['version']
                pkg_name = PACKAGE_DATA[pkg]['name']
                latest_version = select_latest_version(cur_ver, libio_ver, latest_ver, pkg_name)
                if latest_version != cur_ver:
                    FINAL_DATA[repo]['notify'] = "true"
                    tmp_json['ecosystem'] = REPO_DATA[repo]['ecosystem']
                    tmp_json['name'] = pkg_name
                    tmp_json['version'] = cur_ver
                    tmp_json['latest_version'] = latest_version
                    tmp_lst.append(tmp_json)
        FINAL_DATA[repo]['version_updates'] = tmp_lst[:]


def check_license_compatibility():
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

            if is_conflict == "true":
                FINAL_DATA[repo]['notify'] = 'false'


def generate_notification_payload():
    final_payload = []
    for data in FINAL_DATA:
        repo_data = FINAL_DATA[data]
        if repo_data['notify'] == 'true':
            tmp_json = {"data": {
                            "attributes": {
                                "custom": {
                                    "repo_url": "",
                                    "version_updates": []
                                },
                                "id": "",
                                "type": "analytics.notify.version"
                            }
                       },
                         "id": str(uuid4()),
                         "type": "notifications"
            }
            tmp_json['data']['attributes']['custom']['repo_url'] = data
            tmp_json['data']['attributes']['id'] = data
            tmp_json['data']['attributes']['custom']['version_updates'] = repo_data['version_updates']
            final_payload.append(tmp_json)
    print("<---Repo Data--->")
    print(REPO_DATA)
    print("<---Package Data--->")
    print(PACKAGE_DATA)
    print("<---New Version Data--->")
    print(NEW_VERSION_DATA)
    print("<---Version Data--->")
    print(VERSION_DATA)
    print("<---Final Data--->")
    print(FINAL_DATA)
    print("<-------------Payload for Notification------------->")
    print(final_payload)


if __name__ == "__main__":
    run()


