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

"""Sends notification to users."""


import os
from time import strftime, gmtime
from uuid import uuid4
import requests
import logging


class UserNotification:
    """Class to connect OSIO Notification service."""

    @staticmethod
    def send_notification(notification, token):
        """Send notification to the OSIO notification service."""
        url = os.getenv('NOTIFICATION_SERVICE_HOST', '').strip()
        print("****************Notificaion host************")
        print(url)
        endpoint = '{url}/api/notify'.format(url=url)
        auth = 'Bearer {token}'.format(token=token)
        for notify_ in notification:
            resp = requests.post(endpoint, json=notify_, headers={'Authorization': auth})
            if resp.status_code != 202:
                raise resp.raise_for_status()

        return {'status': 'success'}
