#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

__author__ = "TrackMe Limited"
__copyright__ = "Copyright 2023, TrackMe Limited, U.K."
__credits__ = "TrackMe Limited, U.K."
__license__ = "TrackMe Limited, all rights reserved"
__version__ = "0.1.0"
__maintainer__ = "TrackMe Limited, U.K."
__email__ = "support@trackme-solutions.com"
__status__ = "PRODUCTION"

# Standard library imports
import os
import sys
import re
import json
import random
import time
import logging
from logging.handlers import RotatingFileHandler

# Networking and URL handling imports
import requests
from requests.structures import CaseInsensitiveDict
from urllib.parse import urlencode
import urllib.parse
import urllib3

# Disable insecure request warnings for urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# splunk home
splunkhome = os.environ["SPLUNK_HOME"]

# appebd lib
sys.path.append(os.path.join(splunkhome, "etc", "apps", "TA-trackme-cribl", "lib"))

# import Splunk libs
import splunklib.client as client
import splunklib.results as results

# logging:
# To avoid overriding logging destination of callers, the libs will not set on purpose any logging definition
# and rely on callers themselves


def cribl_reqinfo(session_key, splunkd_uri):
    """
    Retrieve request info & settings.
    """

    # Ensure splunkd_uri starts with "https://"
    if not splunkd_uri.startswith("https://"):
        splunkd_uri = f"https://{splunkd_uri}"

    # Build header and target URL
    headers = CaseInsensitiveDict()
    headers["Authorization"] = f"Splunk {session_key}"
    target_url = f"{splunkd_uri}/services/cribl/v1/request_info"

    # Create a requests session for better performance
    session = requests.Session()
    session.headers.update(headers)

    try:
        # Use a context manager to handle the request
        with session.get(target_url, verify=False) as response:
            if response.ok:
                logging.debug(f'Success retrieving conf, data="{response}"')
                response_json = response.json()
                return response_json
            else:
                error_message = f'Failed to retrieve conf, status_code={response.status_code}, response_text="{response.text}"'
                logging.error(error_message)
                raise Exception(error_message)

    except Exception as e:
        error_message = f'Failed to retrieve conf, exception="{str(e)}"'
        logging.error(error_message)
        raise Exception(error_message)


def cribl_getloglevel(system_authtoken, splunkd_port):
    """
    Simply get and return the loglevel with elevated privileges to avoid code duplication
    """

    # Get service
    service = client.connect(
        owner="nobody",
        app="TA-trackme-cribl",
        port=splunkd_port,
        token=system_authtoken,
    )

    # set loglevel
    loglevel = "INFO"
    conf_file = "ta_trackme_cribl_settings"
    confs = service.confs[str(conf_file)]
    for stanza in confs:
        if stanza.name == "logging":
            for stanzakey, stanzavalue in stanza.content.items():
                if stanzakey == "loglevel":
                    loglevel = stanzavalue

    return loglevel


def get_cribl_api_token(connection_info):
    headers = {"accept": "application/json", "Content-Type": "application/json"}
    session = requests.session()

    logging.info(f"get_cribl_api_token connection_info={connection_info}")

    cribl_deployment_type = connection_info.get("cribl_deployment_type")
    cribl_onprem_leader_url = connection_info.get("cribl_onprem_leader_url")
    cribl_client_id = connection_info.get("cribl_client_id")
    cribl_client_secret = connection_info.get("cribl_client_secret")

    if cribl_deployment_type == "onprem":
        # Enforce https scheme and remove trailing slash in the URL, if any
        cribl_onprem_leader_url = (
            f"https://{cribl_onprem_leader_url.replace('https://', '').rstrip('/')}"
        )

        response = session.post(
            f"{cribl_onprem_leader_url}/api/v1/auth/login",
            json={"username": cribl_client_id, "password": cribl_client_secret},
            verify=True,
            headers=headers,
        )

        if response.status_code == 200:
            res = response.json()
            token = f'Bearer {res["token"]}'
            return token
        else:
            error_msg = f"Failed to authenticate against Cribl on-premise API with response.code: {response.status_code}, response.text: {response.text}."
            logging.error(error_msg)
            raise Exception(error_msg)

    elif cribl_deployment_type == "cloud":
        response = session.post(
            "https://login.cribl.cloud/oauth/token",
            json={
                "grant_type": "client_credentials",
                "client_id": cribl_client_id,
                "client_secret": cribl_client_secret,
                "audience": "https://api.cribl.cloud",
            },
            verify=True,
            headers=headers,
        )

        if response.status_code == 200:
            res = response.json()
            token = f'Bearer {res["access_token"]}'
            return token
        else:
            error_msg = f"Failed to authenticate against Cribl Cloud API with response.code: {response.status_code}, response.text: {response.text}."
            logging.error(error_msg)
            raise Exception(error_msg)


def cribl_test_remote_connectivity(connection_info):
    cribl_client_id = connection_info.get("cribl_client_id")
    cribl_client_secret = connection_info.get("cribl_client_secret")

    logging.info(f"cribl_test_remote_connectivity connection_info={connection_info}")

    if not cribl_client_id or not cribl_client_secret:
        raise Exception(
            {
                "status": "failure",
                "message": "API credentials must be provided, cannot proceed!",
            }
        )

    try:
        cribl_api_token = get_cribl_api_token(connection_info)

        return {
            "status": "success",
            "message": "Cribl API connectivity check was successful, service was established",
            "cribl_api_token": cribl_api_token,
        }

    except Exception as e:
        error_msg = (
            f'Cribl API has failed at connectivitity check, exception="{str(e)}"'
        )
        logging.error(error_msg)
        raise Exception(
            {
                "message": "Cribl API check failed at connectivity verification",
                "exception": str(e),
            }
        )
