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

"""Utils functions for Github usage."""

import json
from git import Repo
from pathlib import Path, PurePath
import xml.etree.ElementTree as ET
from datetime import datetime
from requests_futures.sessions import FuturesSession

_session = FuturesSession(max_workers=100)
_changed_files = []
_branch_name = "OSIO_Notification_"+datetime.utcnow().strftime("%d-%m-%y")
_dir_path = "/home/yzainee/clonedRepos"


def get_gh_token():
    """Get the GH token via auth"""
    return "ab623225fe53d57c40f48ff00116de5143f0be26"


def get_gh_user(git_url):
    """Get the GH username"""
    return git_url.split("//")[1].split("/")[1]


def get_gh_project(git_url):
    """Get the GH username"""
    return git_url.split("//")[1].split("/")[2]


def create_pull_request(git_url):
    """Create PR on the repository"""
    print("create_pull_request() started")
    payload = {
        "title": "Newer Versions Notification",
        "body": "Newer Versions Notification - OSIO Feature",
        "head": get_gh_user(git_url) + ":" + _branch_name,
        "base": "master"
    }
    _session.headers['Authorization'] = "token " + get_gh_token()
    _session.headers['Accept'] = "application/vnd.github.v3+json"
    _session.post('https://api.github.com/repos/{0}/{1}/pulls'.
                  format(get_gh_user(git_url), get_gh_project(git_url)), json=payload)
    print("create_pull_request() ended")


def clone_repo(repo_url):
    """Clone the repository"""
    print("clone_repo() started")
    gh_token = get_gh_token()
    url = "https://" + gh_token + ":x-oauth-basic@" + repo_url.split("//")[1]
    repo = Repo.clone_from(url, _dir_path + "/" + repo_url.split("/")[-1])
    repo.create_head(_branch_name)
    repo.git.checkout(_branch_name)
    repo.git.pull("origin", "master")
    print("clone_repo() ended")
    return repo


def fetch_maven_dep_files(git_url):
    return list(Path(_dir_path + "/" + get_gh_project(git_url)).rglob("pom.xml"))


def find_and_modify_maven_file(files, dir_deps):
    del _changed_files[:]
    for dep in dir_deps:
        pkg_name = dep['name']
        version = dep['latest_version']
        group_id = pkg_name.split(":")[0]
        artifact_id = pkg_name.split(":")[1]
        for file in files:
            tree = ET.parse(file)
            root = tree.getroot()
            ns = root.tag[1:].split("}")[0]
            namespace = "{" + ns + "}"
            ET.register_namespace('', ns)
            # print(root.findall(".//{0}dependency[{0}groupId and {0}artifactId]".format(namespace)))
            for elem in root.findall(".//{0}dependency".format(namespace)):
                elem_group_id = elem.find('{0}groupId'.format(namespace)).text
                elem_art_id = elem.find('{0}artifactId'.format(namespace)).text
                if elem_group_id == group_id and elem_art_id == artifact_id:
                    version_node = elem.find('{0}version'.format(namespace))
                    if version_node is None:
                        version_node = ET.SubElement(elem, 'version')
                        version_node.text = version
                    else:
                        version_node.text = version
            _changed_files.append(file)
            tree.write(file, encoding="UTF-8", xml_declaration=True)


def fetch_dependency_files(eco, dir_deps, git_url):
    """Redirect the flow based on eco system"""
    print("fetch_dependency_files() started")
    if eco == "maven":
        files = fetch_maven_dep_files(git_url)
        find_and_modify_maven_file(files, dir_deps)
    print("fetch_dependency_files() ended")


def commit_changed_files(repo):
    """Perform the GH commit"""
    print("commit_changed_files() started")
    repo.git.add(list(set(_changed_files)))
    repo.git.commit("-m", "Newer versions available")
    print("commit_changed_files() ended")


def start_gh_operation(data):
    """Perform the GH operations"""
    print("start_gh_operation() started")
    for json_data in data:
        git_url = json_data['data']['attributes']['custom']['repo_url']
        repo = clone_repo(git_url)
        dir_deps = json_data['data']['attributes']['custom']['direct_updates']
        eco = dir_deps[0]['ecosystem']
        fetch_dependency_files(eco, dir_deps, git_url)
        commit_changed_files(repo)
        create_pull_request(git_url)
    print("start_gh_operation() ended")


if __name__ == '__main__':
    print("start main")
    with open('./f8a_notification/sample.json') as f:
        data = json.load(f)
    start_gh_operation(data)



