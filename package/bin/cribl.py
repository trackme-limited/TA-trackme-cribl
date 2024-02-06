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

# Built-in libraries
import json
import logging
import os
import sys
import time
from ast import literal_eval

# Third-party libraries
import requests
import urllib3

# Logging handlers
from logging.handlers import RotatingFileHandler

# Disable insecure request warnings for urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# splunk home
splunkhome = os.environ["SPLUNK_HOME"]

# set logging
filehandler = RotatingFileHandler(
    "%s/var/log/splunk/cribl.log" % splunkhome,
    mode="a",
    maxBytes=10000000,
    backupCount=1,
)
formatter = logging.Formatter(
    "%(asctime)s %(levelname)s %(filename)s %(funcName)s %(lineno)d %(message)s"
)
logging.Formatter.converter = time.gmtime
filehandler.setFormatter(formatter)
log = logging.getLogger()  # root logger - Good to get it only once.
for hdlr in log.handlers[:]:  # remove the existing file handlers
    if isinstance(hdlr, logging.FileHandler):
        log.removeHandler(hdlr)
log.addHandler(filehandler)  # set the new handler
# set the log level to INFO, DEBUG as the default is ERROR
log.setLevel(logging.INFO)

# append lib
sys.path.append(os.path.join(splunkhome, "etc", "apps", "TA-trackme-cribl", "lib"))

# Import Splunk libs
from splunklib.searchcommands import (
    dispatch,
    GeneratingCommand,
    Configuration,
    Option,
    validators,
)

# Import trackme libs
from cribl_libs import cribl_reqinfo, cribl_api_token_for_account


# get current user and roles membership
def get_user_roles(self):
    """
    Retrieve current user and his roles.
    """

    # get current user
    username = self._metadata.searchinfo.username

    # get user info
    users = self.service.users

    # Get roles for the current user
    username_roles = []
    for user in users:
        if user.name == username:
            username_roles = user.roles
    logging.debug('username="{}", roles="{}"'.format(username, username_roles))

    # return current user roles as a list
    return username_roles


def get_request_target_type(account):
    if not account:
        return "splunk"
    return "cribl"


def validate_url(target_type, url):
    if target_type == "splunk" and not url.startswith("/services/cribl/"):
        error_msg = "API url is invalid and should start with: /services/cribl/ if target is an internal Splunk API endpoint to this application"
        logging.error(error_msg)
        raise Exception(error_msg)
    elif target_type == "cribl" and not url.startswith("/api/"):
        error_msg = "API url is invalid and should start with: /api/ when target is a Cribl API endpoint"
        logging.error(error_msg)
        raise Exception(error_msg)


def prepare_target_url_for_cribl(account_info, url):
    cribl_deployment_type = account_info.get("cribl_deployment_type")
    if cribl_deployment_type == "cloud":
        return f"https://main-{account_info.get('cribl_cloud_organization_id')}.cribl.cloud{url}"
    if cribl_deployment_type == "onprem":
        cribl_onprem_leader_url = account_info.get("cribl_onprem_leader_url")
        if not cribl_onprem_leader_url.startswith("https://"):
            cribl_onprem_leader_url = "https://" + cribl_onprem_leader_url
        return f"{cribl_onprem_leader_url.rstrip('/')}{url}"


def prepare_target_url_groups_for_cribl(account_info):
    cribl_deployment_type = account_info.get("cribl_deployment_type")
    groups_url = f"/api/v1/master/groups?product=stream"
    if cribl_deployment_type == "cloud":
        return f"https://main-{account_info.get('cribl_cloud_organization_id')}.cribl.cloud{groups_url}"
    if cribl_deployment_type == "onprem":
        cribl_onprem_leader_url = account_info.get("cribl_onprem_leader_url")
        if not cribl_onprem_leader_url.startswith("https://"):
            cribl_onprem_leader_url = "https://" + cribl_onprem_leader_url
        return f"{cribl_onprem_leader_url.rstrip('/')}{groups_url}"


def prepare_target_url_routes_for_cribl(account_info, group):
    cribl_deployment_type = account_info.get("cribl_deployment_type")
    routes_url = f"/api/v1/m/{group}/routes"
    if cribl_deployment_type == "cloud":
        return f"https://main-{account_info.get('cribl_cloud_organization_id')}.cribl.cloud{routes_url}"
    if cribl_deployment_type == "onprem":
        cribl_onprem_leader_url = account_info.get("cribl_onprem_leader_url")
        if not cribl_onprem_leader_url.startswith("https://"):
            cribl_onprem_leader_url = "https://" + cribl_onprem_leader_url
        return f"{cribl_onprem_leader_url.rstrip('/')}{routes_url}"


def prepare_target_url_conf_for_cribl(account_info, group):
    cribl_deployment_type = account_info.get("cribl_deployment_type")
    conf_url = f"/api/v1/m/{group}/system/settings/conf"
    if cribl_deployment_type == "cloud":
        return f"https://main-{account_info.get('cribl_cloud_organization_id')}.cribl.cloud{conf_url}"
    if cribl_deployment_type == "onprem":
        cribl_onprem_leader_url = account_info.get("cribl_onprem_leader_url")
        if not cribl_onprem_leader_url.startswith("https://"):
            cribl_onprem_leader_url = "https://" + cribl_onprem_leader_url
        return f"{cribl_onprem_leader_url.rstrip('/')}{conf_url}"


def prepare_request_body(body):
    try:
        return json.dumps(json.loads(body), indent=1)
    except ValueError:
        return json.dumps(literal_eval(body), indent=1)


@Configuration(distributed=False)
class CriblRestHandler(GeneratingCommand):
    url = Option(
        doc=""" **Syntax:** **The endpoint URL=**** **Description:** Mandatory, the endpoint URL""",
        require=True,
        default=None,
        validate=validators.Match("url", r"^.*"),
    )

    account = Option(
        doc=""" **Syntax:** **The cribl account=**** **Description:** Mandatory if running a call against the Cribl API""",
        require=False,
        default=None,
        validate=validators.Match("account", r"^.*$"),
    )

    cribl_function = Option(
        doc=""" **Syntax:** **The cribl_function=**** **Description:** Optional, a prebuilt cribl function""",
        require=False,
        default=None,
        validate=validators.Match(
            "mode",
            r"^(?:get_global_metrics|get_destinations_metrics|get_pipelines_metrics|get_routes_metrics|get_sources_metrics|get_groups_conf)$",
        ),
    )

    mode = Option(
        doc=""" **Syntax:** **The HTTP mode=**** **Description:** Optional, the HTTP mode to be used for the REST API call""",
        require=False,
        default="get",
        validate=validators.Match("mode", r"^(?:get|post|delete)$"),
    )

    body = Option(
        doc=""" **Syntax:** **The HTTP body data=**** **Description:** Optional, the HTTP data to be used for the REST API call, optional for get and mandatory for post/delete calls""",
        require=False,
        default=None,
    )

    def generate(self, **kwargs):
        start = time.time()

        # get reqinfo
        reqinfo = cribl_reqinfo(
            self._metadata.searchinfo.session_key, self._metadata.searchinfo.splunkd_uri
        )

        # set logging_level
        logginglevel = logging.getLevelName(reqinfo["logging_level"])
        log.setLevel(logginglevel)

        # init headers
        headers = {}

        # session key
        session_key = self._metadata.searchinfo.session_key

        # earliest & latest
        earliest = self._metadata.searchinfo.earliest_time
        latest = self._metadata.searchinfo.latest_time
        timerange = float(latest) - float(earliest)

        # identify target_type
        target_type = get_request_target_type(self.account)
        validate_url(target_type, self.url)

        if target_type == "cribl":
            account_info = cribl_api_token_for_account(
                self._metadata.searchinfo.session_key,
                self._metadata.searchinfo.splunkd_uri,
                self.account,
            )

            # RBAC
            rbac_roles = account_info.get("rbac_roles")

            # check RBAC
            user_roles = get_user_roles(self)
            rbac_granted = False

            for user_role in user_roles:
                if user_role in rbac_roles:
                    rbac_granted = True
                    break

            # grant the system user
            if self._metadata.searchinfo.username in ("splunk-system-user", "admin"):
                rbac_granted = True

            if not rbac_granted:
                logging.debug(
                    f'RBAC access not granted to this account, user_roles="{user_roles}", account_roles="{rbac_roles}", username="{self._metadata.searchinfo.username}"'
                )
                raise Exception(
                    "Access to this account has been refused, please contact your TrackMe administrator to grant access to this account"
                )
            else:
                logging.debug(
                    f'RBAC access granted to this account, user_roles="{user_roles}", account_roles="{rbac_roles}"'
                )

            headers["Authorization"] = account_info.get("cribl_token")
            target_url = prepare_target_url_for_cribl(account_info, self.url)

            # ssl verification
            cribl_ssl_verify = int(account_info.get("cribl_ssl_verify", 1))
            cribl_ssl_certificate_path = account_info.get(
                "cribl_ssl_certificate_path", None
            )

            if cribl_ssl_verify == 0:
                verify_ssl = False
            elif cribl_ssl_certificate_path and os.path.isfile(
                cribl_ssl_certificate_path
            ):
                verify_ssl = cribl_ssl_certificate_path
            else:
                verify_ssl = True

        else:
            headers["Authorization"] = f"Splunk {session_key}"
            target_url = f"{reqinfo['server_rest_uri']}/{self.url}"
            # Internal communication with splunkd on the loopback, must not verify
            verify_ssl = False

        if self.body:
            json_data = prepare_request_body(self.body)
            headers["Content-Type"] = "application/json"
        else:
            json_data = None

        #
        # free API call
        #

        if not self.cribl_function:
            if self.mode == "get":
                response = requests.get(target_url, headers=headers, verify=verify_ssl)
            elif self.mode == "post":
                response = requests.post(
                    target_url, headers=headers, data=json_data, verify=verify_ssl
                )

            elif self.mode == "delete":
                response = requests.delete(
                    target_url, headers=headers, data=json_data, verify=verify_ssl
                )
            else:
                raise Exception(f"Unsupported mode: {self.mode}")

            if response.status_code not in [200, 201, 202]:
                logging.error(
                    f"HTTP request failed with status code: {response.status_code}, response: {response.text}"
                )
                logging.error(f"Content: {response.content}")
                raise Exception(
                    f"HTTP request failed with status code: {response.status_code}, response: {response.text}"
                )

            try:
                response_data = response.json()
                logging.debug(
                    f"response.status_code={response.status_code}, response.text={response.text}"
                )

                if "items" in response_data and isinstance(
                    response_data["items"], list
                ):
                    # Check if the 'items' list is empty
                    if not response_data["items"]:
                        yield {
                            "_time": time.time(),
                            "_raw": response.text,
                        }
                        return

                    # If 'items' is not empty, proceed to process each item
                    for item in response_data["items"]:
                        # Check if the item is a dictionary (or dict-like) before accessing its keys
                        if isinstance(item, dict):
                            if "id" in item:
                                item_id = item["id"]
                            else:
                                item_id = None

                            if "conf" in item:
                                # If 'conf' exists in the item, yield that specifically
                                item_result = item["conf"]

                                # add id
                                if item_id:
                                    item_result["id"] = item_id

                                yield_result = {}
                                yield_result["_time"] = time.time()
                                yield_result["_raw"] = item_result

                                if item_id:
                                    yield_result["id"] = item_id

                                # result
                                result = yield_result

                            else:
                                # If 'conf' doesn't exist in the item, yield the entire item
                                result = {
                                    "_time": time.time(),
                                    "_raw": json.dumps(item),
                                }
                        elif isinstance(item, list):
                            for subitem in item:
                                # item itself is a list
                                result = {
                                    "_time": time.time(),
                                    "_raw": subitem,
                                }

                        else:
                            # If the item isn't a dictionary nor a list, just yield the item as-is
                            logging.info(f"yield item {str(item)}")
                            result = {
                                "_time": time.time(),
                                "_raw": response.text,
                            }

                        yield result

                else:
                    # For other cases, just yield the entire response content
                    yield {
                        "_time": time.time(),
                        "_raw": response.content.decode("utf-8"),
                    }

            except json.JSONDecodeError:
                # If the response isn't valid JSON, return the plain text of the response
                logging.debug(
                    f"response is plain text, attempting to detect JSON in response"
                )

                try:
                    # Split the response text into individual JSON strings
                    response_items = response.text.strip().split("\n")

                    # Process each JSON string
                    for item in response_items:
                        try:
                            json_item = json.loads(item)
                            yield {
                                "_time": json_item.get("_time", time.time()),
                                "_raw": json_item,
                            }
                        except json.JSONDecodeError:
                            logging.error(f"Invalid JSON: {item}")

                except Exception as e:
                    yield {
                        "_time": time.time(),
                        "_raw": response.text,
                    }

        #
        # pre-built cribl function
        #

        else:
            # timeWindowSeconds should be adapted (rolling up with > 3 hours)
            if float(timerange) > 10800:
                timeWindowSeconds = 600
            else:
                timeWindowSeconds = 10

            logging.debug(
                f"cribl_function timeWindowSeconds={timeWindowSeconds} with timerange={timerange}"
            )

            if self.cribl_function == "get_global_metrics":
                data = {
                    "where": '(has_no_dimensions) && (__dist_mode=="worker")',
                    "aggs": {
                        "aggregations": [
                            'sum("total.in_events").as("eventsIn")',
                            'sum("total.out_events").as("eventsOut")',
                            'sum("total.in_bytes").as("bytesIn")',
                            'sum("total.out_bytes").as("bytesOut")',
                        ],
                        "timeWindowSeconds": timeWindowSeconds,
                    },
                    "earliest": f"{timerange}s",
                    "latest": time.time(),
                }

            elif self.cribl_function == "get_destinations_metrics":
                data = {
                    "where": '((output != null) && (__worker_group != null)) && ((!!output) && (__dist_mode=="worker"))',
                    "aggs": {
                        "splitBys": ["output", "__worker_group"],
                        "aggregations": [
                            'sum("total.out_events").as("eventsOut")',
                            'sum("total.out_bytes").as("bytesOut")',
                            'sum("total.dropped_events").as("eventsDropped")',
                            'max("health.outputs").as("health")',
                            'max("backpressure.outputs").as("backpressure")',
                        ],
                        "timeWindowSeconds": timeWindowSeconds,
                    },
                    "earliest": f"{timerange}s",
                    "latest": time.time(),
                }

            elif self.cribl_function == "get_pipelines_metrics":
                data = {
                    "where": '((id != null) && (__worker_group != null)) && ((project == null) && (__dist_mode=="worker"))',
                    "aggs": {
                        "aggregations": [
                            'sum("pipe.out_events").as("eventsOut")',
                            'sum("pipe.in_events").as("eventsIn")',
                            'sum("pipe.dropped_events").as("eventsDropped")',
                        ],
                        "splitBys": ["id", "__worker_group"],
                        "timeWindowSeconds": timeWindowSeconds,
                    },
                    "earliest": f"{timerange}s",
                    "latest": time.time(),
                }

            elif self.cribl_function == "get_routes_metrics":
                data = {
                    "aggs": {
                        "aggregations": [
                            'sum("route.out_events").as("eventsOut")',
                            'sum("route.out_bytes").as("bytesOut")',
                            'sum("route.in_events").as("eventsIn")',
                            'sum("route.in_bytes").as("bytesIn")',
                            'sum("route.dropped_events").as("eventsDropped")',
                        ],
                        "splitBys": ["id", "__worker_group"],
                        "timeWindowSeconds": timeWindowSeconds,
                    },
                    "earliest": f"{timerange}s",
                    "latest": time.time(),
                    "where": '((id != null) && (__worker_group != null)) && (__dist_mode=="worker")',
                }

            elif self.cribl_function == "get_sources_metrics":
                data = {
                    "where": '((input != null) && (__worker_group != null)) && ((!!input) && (__dist_mode=="worker"))',
                    "aggs": {
                        "aggregations": [
                            'sum("total.in_events").as("eventsIn")',
                            'sum("total.in_bytes").as("bytesIn")',
                            'max("health.inputs").as("health")',
                        ],
                        "splitBys": ["input", "__worker_group"],
                        "timeWindowSeconds": timeWindowSeconds,
                    },
                    "earliest": f"{timerange}s",
                    "latest": time.time(),
                }

            # for routes, we need to retrieve the routes definition first
            if self.cribl_function == "get_routes_metrics":
                # get groups
                groups_url = prepare_target_url_groups_for_cribl(account_info)
                response_groups = requests.get(
                    groups_url, headers=headers, verify=verify_ssl
                )
                response_groups_items = response_groups.json().get("items")
                # form a list of groups
                groups_list = []
                for item in response_groups_items:
                    groups_list.append(item.get("id"))

                # init a dict
                routes_dict = {}

                # loop through the groups, and get the routes
                for group in groups_list:
                    routes_url = prepare_target_url_routes_for_cribl(
                        account_info, group
                    )
                    response_routes = requests.get(
                        routes_url, headers=headers, verify=verify_ssl
                    )
                    routes_items = response_routes.json().get("items")
                    logging.debug(f"routes_item={routes_items}")

                    # Loop through the route items
                    for route_item in routes_items:
                        routes = route_item.get("routes")

                        # finally loop through the routes and populates our dict
                        for route in routes:
                            route_id = route.get("id")
                            route_name = route.get("name")
                            routes_dict[route_id] = route_name

                # debug only
                logging.debug(f"routes_dict={routes_dict}")

                # get response
                response = requests.post(
                    target_url, headers=headers, json=data, verify=verify_ssl
                )

            elif self.cribl_function == "get_groups_conf":
                # get groups
                groups_url = prepare_target_url_groups_for_cribl(account_info)
                response_groups = requests.get(
                    groups_url, headers=headers, verify=verify_ssl
                )
                response_groups_items = response_groups.json().get("items")
                # form a list of groups
                groups_list = []
                for item in response_groups_items:
                    groups_list.append(item.get("id"))

                # init a dict
                groups_conf_dict = {}

                # loop through the groups, and get the conf
                for group in groups_list:
                    conf_url = prepare_target_url_conf_for_cribl(account_info, group)
                    response_conf = requests.get(
                        conf_url, headers=headers, verify=verify_ssl
                    )
                    conf_items = response_conf.json()
                    logging.debug(f"conf_items={conf_items}")

                    # add to dict
                    groups_conf_dict[group] = conf_items

                # yield each group conf
                for group, conf_items in groups_conf_dict.items():
                    yield {
                        "_time": time.time(),
                        "group": group,
                        "_raw": conf_items,
                    }

                # no need to continue further
                return 0

            else:
                response = requests.post(
                    target_url, headers=headers, json=data, verify=verify_ssl
                )

            if response.status_code not in [200, 201, 202]:
                logging.error(
                    f"HTTP request failed with status code: {response.status_code}, response: {response.text}"
                )
                logging.error(f"Content: {response.content}")
                raise Exception(
                    f"HTTP request failed with status code: {response.status_code}, response: {response.text}"
                )

            # parse
            response_data = response.json()
            results = response_data["results"]

            for result in results:
                if self.cribl_function == "get_global_metrics":
                    yield {
                        "_time": result["endtime"],
                        "_raw": result,
                        "bytesIn": result.get("bytesIn", 0),
                        "bytesOut": result.get("bytesOut", 0),
                        "eventsIn": result.get("eventsIn", 0),
                        "eventsOut": result.get("eventsOut", 0),
                    }

                elif self.cribl_function == "get_destinations_metrics":
                    yield {
                        "_time": result["endtime"],
                        "_raw": result,
                        "worker_group": result.get("__worker_group", "unknown"),
                        "destination": result.get("output", "unknown"),
                        "bytesOut": result.get("bytesOut", 0),
                        "eventsOut": result.get("eventsOut", 0),
                        "eventsDropped": result.get("eventsDropped", 0),
                        "health": result.get("health", 0),
                        "backpressure": result.get("backpressure", 0),
                    }

                elif self.cribl_function == "get_pipelines_metrics":
                    yield {
                        "_time": result["endtime"],
                        "_raw": result,
                        "worker_group": result.get("__worker_group", "unknown"),
                        "pipeline": result.get("id", "unknown"),
                        "eventsOut": result.get("eventsOut", 0),
                        "eventsIn": result.get("eventsIn", 0),
                        "eventsDropped": result.get("eventsDropped", 0),
                    }

                elif self.cribl_function == "get_routes_metrics":
                    # enrich with the route names
                    route_id = result.get("id", "unknown")
                    try:
                        route_name = routes_dict[route_id]
                        result["route"] = route_name
                    except Exception as e:
                        route_name = "unknown"

                    yield {
                        "_time": result["endtime"],
                        "_raw": result,
                        "worker_group": result.get("__worker_group", "unknown"),
                        "route_id": route_id,
                        "route": route_name,
                        "bytesIn": result.get("bytesIn", 0),
                        "bytesOut": result.get("bytesOut", 0),
                        "eventsIn": result.get("eventsIn", 0),
                        "eventsOut": result.get("eventsOut", 0),
                        "eventsDropped": result.get("eventsDropped", 0),
                    }

                elif self.cribl_function == "get_sources_metrics":
                    yield {
                        "_time": result["endtime"],
                        "_raw": result,
                        "worker_group": result.get("__worker_group", "unknown"),
                        "source": result.get("input", "unknown"),
                        "bytesIn": result.get("bytesIn", 0),
                        "eventsIn": result.get("eventsIn", 0),
                        "health": result.get("health", 0),
                    }

        logging.debug(
            f"response.text={response.text}, response.status_code={response.status_code}"
        )
        # Log the run time
        logging.info(
            f"cribl API command has terminated, response is logged in debug mode only, run_time={round(time.time() - start, 3)}"
        )


dispatch(CriblRestHandler, sys.argv, sys.stdin, sys.stdout, __name__)
