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

"""Utils functions for generic usage."""

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import requests
import semantic_version as sv
import traceback
import json
import logging
import os

GREMLIN_SERVER_URL_REST = "http://{host}:{port}".format(
    host=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_HOST", "localhost"),
    port=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_PORT", "8182"))

LICENSE_SCORING_URL_REST = "http://{host}:{port}".format(
    host=os.environ.get("LICENSE_SERVICE_HOST", "localhost"),
    port=os.environ.get("LICENSE_SERVICE_PORT", "6162"))

zero_version = sv.Version("0.0.0")
logger = logging.getLogger(__name__)


def convert_version_to_proper_semantic(version, package_name=None):
    """Perform Semantic versioning.

    : type version: string
    : param version: The raw input version that needs to be converted.
    : type return: semantic_version.base.Version
    : return: The semantic version of raw input version.
    """
    conv_version = sv.Version.coerce('0.0.0')
    try:
        if version in ('', '-1', None):
            version = '0.0.0'
        """Needed for maven version like 1.5.2.RELEASE to be converted to
        1.5.2 - RELEASE for semantic version to work."""
        version = version.replace('.', '-', 3)
        version = version.replace('-', '.', 2)
        # Needed to add this so that -RELEASE is account as a Version.build
        version = version.replace('-', '+', 3)
        conv_version = sv.Version.coerce(version)
    except ValueError:
        logger.info(
            "Unexpected ValueError for the package {} due to version {}"
            .format(package_name, version))
        pass
    finally:
        return conv_version


def version_info_tuple(version):
    """Return the sem_version information  (major, minor, patch, build).

    : type version: semantic_version.base.Version
    : param version: The semantic version whole details are needed.
    : return: A tuple in form of Version.(major, minor, patch, build)
    """
    if isinstance(version, sv.Version):
        return(version.major,
               version.minor,
               version.patch,
               version.build)
    return (0, 0, 0, tuple())


def select_latest_version(input_version='',
                          libio='',
                          anitya='',
                          package_name=None):
    """Select latest version from input sequence(s)."""
    libio_sem_version = convert_version_to_proper_semantic(libio, package_name)
    anitya_sem_version = convert_version_to_proper_semantic(
        anitya, package_name)
    input_sem_version = convert_version_to_proper_semantic(
        input_version, package_name)
    return_version = ''

    try:
        if libio_sem_version == zero_version\
                and anitya_sem_version == zero_version\
                and input_sem_version == zero_version:
            return_version = ''
        else:
            return_version = input_version
            libio_tuple = version_info_tuple(libio_sem_version)
            anitya_tuple = version_info_tuple(anitya_sem_version)
            input_tuple = version_info_tuple(input_sem_version)

            if libio_tuple >= anitya_tuple \
                    and libio_tuple >= input_tuple:
                return_version = libio
            elif anitya_tuple >= libio_tuple \
                    and anitya_tuple >= input_tuple:
                return_version = anitya
    except ValueError:
        """In case of failure let's not show any latest version at all.
        Also, no generation of stack trace,
        as we are only interested in the package that is causing the error."""
        logger.info(
            "Error while selecting "
            "latest version for package {}. Debug:{}"
            .format(package_name,
                    {'input_version': input_version,
                     'libio': libio,
                     'anitya': anitya}))
        return_version = ''
        pass
    finally:
        return return_version


def get_session_retry(retries=3,
                      backoff_factor=0.2,
                      status_forcelist=(404, 500, 502, 504),
                      session=None):
    """Set HTTP Adapter with retries to session."""
    session = session or requests.Session()
    retry = Retry(total=retries, read=retries,
                  connect=retries,
                  backoff_factor=backoff_factor,
                  status_forcelist=status_forcelist)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    return session


def get_response_data(json_response, data_default):
    """Retrieve data from the JSON response.

    Data default parameters takes what should data to be returned.
    """
    return json_response.get("result", {}).get("data", data_default)


def execute_gremlin_dsl(payloads):
    """Execute the gremlin query and return the response."""
    print(GREMLIN_SERVER_URL_REST)
    try:
        resp = get_session_retry().post(GREMLIN_SERVER_URL_REST,
                                        data=json.dumps(payloads))
        if resp.status_code == 200:
            json_response = resp.json()

            return json_response
        else:
            # logger.error("HTTP error {}. Error retrieving Gremlin data."
            # .format(response.status_code))
            return None

    except Exception:
        print(traceback.format_exc())
        # logger.error(traceback.format_exc())
        return None


def check_license_conflict(payload):
    """Check for license conflicts."""
    license_url = LICENSE_SCORING_URL_REST + \
        "/api/v1/stack_license"
    lic_response = get_session_retry().post(license_url,
                                            data=json.dumps(payload))
    resp = lic_response.json()
    if resp['status'] == "Successful":
        return "false"
    else:
        return "true"
