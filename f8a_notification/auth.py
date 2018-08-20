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
# Author: Geetika Batra <gbatra@redhat.com>
#

"""Class to create cron script."""


import os
import requests
import logging as log


class Authentication:
    """Class to generate auth token from OSIO Auth service."""

    @staticmethod
    def init_auth_sa_token():
        """Generate service token for authentication."""
        auth_server_url = os.getenv('AUTH_SERVICE_HOST', '')
        print("*****************auth server url ")
        print(auth_server_url)

        if auth_server_url:
            endpoint = '{url}/api/token'.format(url=auth_server_url)

            client_id = os.getenv('GEMINI_SA_CLIENT_ID', 'id')
            client_secret = os.getenv('GEMINI_SA_CLIENT_SECRET', 'secret')
            payload = {"grant_type": "client_credentials",
                       "client_id": client_id.strip(),
                       "client_secret": client_secret.strip()}

            try:
                log.info('Starting token generation using {url} and {payload}'
                         .format(url=endpoint, payload=payload))
                response = requests.post(endpoint, json=payload)

                log.info('Response status is {status_code}'
                         .format(status_code=response.status_code))
                if response.status_code != 200:
                    response.raise_for_status()

                data = response.json()
                access_token = data.get("access_token")
                if access_token:
                    log.info('Access token successfully generated')
                    return access_token

            except requests.exceptions.RequestException as e:
                raise e

        raise requests.exceptions.RequestException
