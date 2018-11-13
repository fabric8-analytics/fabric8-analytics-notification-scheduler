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
import os
from git import Repo
from pathlib import Path, PurePath
import lxml.etree as ET
from datetime import datetime
from requests_futures.sessions import FuturesSession
import posixpath

_session = FuturesSession(max_workers=100)
_changed_files = []
_branch_name = "OSIO_Notification_" + datetime.utcnow().strftime("%d-%m-%y")
_dir_path = "${HOME}/clonedRepos"
_message = "Newer versions available -OSIO Notification Feature\n" \
           "This PR carries changes in the dependency files which" \
           " were identified by OSIO to be carrying older versions" \
           " of the components. The dependency files have been updated" \
           " with the newer versions available."
_osio_gh_token = "d564bece6f3280235cba7ce34ab3f89c7431923e"


class GithubHelperFunctions:
    """Helper functions for Github usage."""

    def __init__(self):
        """Init function."""
        return None

    def check_collaborator(self, git_url):
        """Check if OSIO user is a collaborator."""
        _session.headers['Authorization'] = "token " + _osio_gh_token
        res = _session.get('https://api.github.com/repos/{0}/{1}/collaborators/{2}'.format(
            self.get_gh_user(git_url),
            self.get_gh_project(git_url),
            "OSIO-Analytics-Notifier"))
        resp = res.result()
        if resp.status_code == 204:
            print("OSIO-Analytics-Notifier is a collaborator")
            return "true"
        return "false"

    def get_gh_token(self):
        """Get the GH token via auth."""
        return _osio_gh_token

    def get_gh_user(self, git_url):
        """Get the GH username."""
        return git_url.split("//")[1].split("/")[1]

    def get_gh_project(self, git_url):
        """Get the GH username."""
        print(git_url)
        return git_url.split("//")[1].split("/")[2]

    def create_pull_request(self, git_url):
        """Create PR on the repository."""
        print("create_pull_request() started")
        payload = {
            "title": "Newer Versions Notification",
            "body": "Newer Versions Notification - OSIO Feature",
            "head": self.get_gh_user(git_url) + ":" + _branch_name,
            "base": "master"
        }
        _session.headers['Authorization'] = "token " + self.get_gh_token()
        _session.headers['Accept'] = "application/vnd.github.v3+json"
        res = _session.post('https://api.github.com/repos/{0}/{1}/pulls'.format(
            self.get_gh_user(git_url),
            self.get_gh_project(git_url)),
            json=payload)
        resp = res.result()
        print("PR creation status code:", resp.status_code)
        resp_content = json.loads(resp.content)
        print(resp_content['html_url'])
        print("create_pull_request() ended")

    def clone_repo(self, repo_url):
        """Clone the repository."""
        print("clone_repo() started")
        gh_token = self.get_gh_token()
        url = "https://" + gh_token + ":x-oauth-basic@" + repo_url.split("//")[1]
        repo = Repo.clone_from(url, _dir_path + "/" + repo_url.split("/")[-1])
        repo.create_head(_branch_name)
        repo.git.checkout(_branch_name)
        repo.git.pull("origin", "master")
        print("clone_repo() ended")
        return repo

    def commit_changed_files(self, repo):
        """Perform the GH commit."""
        print("commit_changed_files() started")
        repo.git.add(list(set(_changed_files)))
        repo.git.commit("-m", _message)
        print("commit_changed_files() ended")


class MavenUpdates:
    """Functions for maven ecosystem."""

    def __init__(self):
        """Init function."""
        self.github_object = GithubHelperFunctions()
        return None

    def fetch_maven_dep_files(self, git_url):
        """Fetch maven dependency files function."""
        project = self.github_object.get_gh_project(git_url)
        return list(Path(_dir_path + "/" + project).rglob("pom.xml"))

    def find_and_modify_maven_file(self, files, dir_deps):
        """Modify the dependency file function."""
        del _changed_files[:]
        for dep in dir_deps:
            pkg_name = dep['name']
            version = dep['latest_version']
            group_id = pkg_name.split(":")[0]
            artifact_id = pkg_name.split(":")[1]
            version_found_flag = "false"
            property_search_flag = "false"
            property_search_text = ""
            print("Searching for " + group_id + ":" + artifact_id)
            for file in files:
                parser = ET.XMLParser(remove_blank_text=True)
                tree = ET.parse(posixpath.normpath(file), parser)
                root = tree.getroot()
                ns = root.tag[1:].split("}")[0]
                for node in root.xpath("//ns:dependency[ns:groupId[text()='" + group_id + "']"
                                       "and ns:artifactId[text()='" + artifact_id + "']]",
                                       namespaces={'ns': ns}):
                    version_node = node.find('ns:version', namespaces={'ns': ns})
                    if version_node is not None:
                        print("Version node present in " + posixpath.normpath(file))
                        version_found_flag = "true"
                        if version_node.text.find("$") == -1:
                            version_node.text = version
                        else:
                            print("Searching version (properties) in current file")
                            version_text = version_node.text[2:-1]
                            property_search_flag = "true"
                            property_search_text = version_text
                            prop = root.xpath("//ns:properties"
                                              "/ns:" + version_text, namespaces={'ns': ns})
                            if prop[0] is not None:
                                prop[0].text = version
                                property_search_flag = "false"
                            else:
                                print("Version not found in properties of current file")
                    else:
                        print("Version node not present")

                if version_found_flag == "false":
                    print("Checking management section for dependencies")
                    for mgt_node in root.xpath("//ns:dependencyManagement/ns:dependencies"
                                               "/ns:dependency[ns:groupId[text()='" + group_id + "']]",
                                               namespaces={'ns': ns}):
                        mgt_ver_node = mgt_node.find('ns:version', namespaces={'ns': ns})
                        if mgt_ver_node is not None:
                            print("Version present in management section")
                            if mgt_ver_node.text.find("$") == -1:
                                mgt_ver_node.text = version
                            else:
                                print("Searching version (properties) in current file")
                                version_text = mgt_ver_node.text[2:-1]
                                property_search_flag = "true"
                                property_search_text = version_text
                                prop = root.xpath("//ns:properties"
                                                  "/ns:" + version_text, namespaces={'ns': ns})
                                if prop[0] is not None:
                                    prop[0].text = version
                                    property_search_flag = "false"
                                else:
                                    print("Version not found in properties of current file")
                        else:
                            print("Adding version in management section")
                            version_node = ET.Element("version")
                            version_node.text = version
                            mgt_node.insert(2, version_node)

                _changed_files.append(file)
                tree.write(posixpath.normpath(file),
                           pretty_print=True,
                           xml_declaration=True,
                           encoding="utf-8")

            if property_search_flag == "true":
                print("Searching version (properties) in parent file")
                for file in files:
                    parser = ET.XMLParser(remove_blank_text=True)
                    tree = ET.parse(posixpath.normpath(file), parser)
                    root = tree.getroot()
                    ns = root.tag[1:].split("}")[0]
                    prop = root.xpath("//ns:properties"
                                      "/ns:" + property_search_text, namespaces={'ns': ns})
                    if prop[0] is not None:
                        prop[0].text = version
                    else:
                        print("Version not found in properties of file" + posixpath.normpath(file))

                _changed_files.append(file)
                tree.write(posixpath.normpath(file),
                           pretty_print=True,
                           xml_declaration=True,
                           encoding="utf-8")


def start_gh_operation(data):
    """Perform the GH operations."""
    print("start_gh_operation() started")
    for json_data in data:
        git_url = json_data['data']['attributes']['custom']['repo_url']
        github_helper = GithubHelperFunctions()
        collab = github_helper.check_collaborator(git_url)
        if collab == "true":
            repo = github_helper.clone_repo(git_url)
            dir_deps = json_data['data']['attributes']['custom']['direct_updates']
            eco = dir_deps[0]['ecosystem']
            fetch_dependency_files(eco, dir_deps, git_url)
            github_helper.commit_changed_files(repo)
            repo.git.push('origin', _branch_name)
            github_helper.create_pull_request(git_url)
        else:
            print("OSIO-Analytics-Notifier is not a collaborator for ", git_url)
    print("start_gh_operation() ended")


def fetch_dependency_files(eco, dir_deps, git_url):
    """Redirect the flow based on eco system."""
    print("fetch_dependency_files() started")
    if eco == "maven":
        maven_updates = MavenUpdates()
        files = maven_updates.fetch_maven_dep_files(git_url)
        maven_updates.find_and_modify_maven_file(files, dir_deps)
    print("fetch_dependency_files() ended")


if __name__ == '__main__':
    print("start main")
    with open('./f8a_notification/sample.json') as f:
        data = json.load(f)
    start_gh_operation(data)

oc login https://devtools-dev.ext.devshift.net:8443 --token=oj_qo-epMuPuj7sZ9u3npcNOWjoEFwX0hAxRfXucPdM