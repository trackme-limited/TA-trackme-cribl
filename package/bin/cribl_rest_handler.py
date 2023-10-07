from __future__ import absolute_import, division, print_function, unicode_literals

__name__ = "cribl_rest_handler.py"
__author__ = "TrackMe Limited U.K"

# Standard library imports
import json
import logging
import os
import re
import sys
import time
import requests
from urllib.parse import urlencode
import urllib.parse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Third-party library imports
from logging.handlers import RotatingFileHandler

# splunk home
splunkhome = os.environ["SPLUNK_HOME"]

# set logging
logger = logging.getLogger(__name__)
filehandler = RotatingFileHandler(
    "%s/var/log/splunk/ta_trackme_cribl_rest_api.log" % splunkhome,
    mode="a",
    maxBytes=10000000,
    backupCount=1,
)
formatter = logging.Formatter(
    "%(asctime)s %(levelname)s %(filename)s %(funcName)s %(lineno)d %(message)s"
)
logging.Formatter.converter = time.gmtime
filehandler.setFormatter(formatter)
log = logging.getLogger()
for hdlr in log.handlers[:]:
    if isinstance(hdlr, logging.FileHandler):
        log.removeHandler(hdlr)
log.addHandler(filehandler)
log.setLevel(logging.INFO)

# append lib
sys.path.append(os.path.join(splunkhome, "etc", "apps", "TA-trackme-cribl", "lib"))

# import API handler
import rest_handler

# import Splunk libs
import splunklib.client as client
import splunklib.results as results

# import Cribl libs
from cribl_libs import cribl_getloglevel, cribl_test_remote_connectivity


class CriblApi_v1(rest_handler.RESTHandler):
    def __init__(self, command_line, command_arg):
        super(CriblApi_v1, self).__init__(command_line, command_arg, logger)

    # Return request info
    def get_request_info(self, request_info, **kwargs):
        describe = False

        # Retrieve from data
        try:
            resp_dict = json.loads(str(request_info.raw_args["payload"]))
        except Exception as e:
            resp_dict = None

        if resp_dict is not None:
            try:
                describe = resp_dict["describe"]
                if describe in ("true", "True"):
                    describe = True
            except Exception as e:
                describe = False
        else:
            # body is not required in this endpoint, if not submitted do not describe the usage
            describe = False

        # if describe is requested, show the usage
        if describe:
            response = {
                "describe": "This endpoint returns the request info such as splunkd_uri and other useful technical information, it requires a GET call with no options",
                "resource_desc": "Return reqinfo",
                "resource_spl_example": '| cribl mode=get url="/services/cribl/v1/request_info"',
            }

            return {"payload": response, "status": 200}

        # Get splunkd port
        splunkd_port = request_info.server_rest_port

        # Get service
        service = client.connect(
            owner="nobody",
            app="TA-trackme-cribl",
            port=splunkd_port,
            token=request_info.system_authtoken,
        )

        # conf
        conf_file = "ta_trackme_cribl_settings"
        confs = service.confs[str(conf_file)]

        # Initialize the trackme_conf dictionary
        ta_trackme_cribl_conf = {}

        # Get conf
        for stanza in confs:
            logging.debug(f'get_trackme_conf, Processing stanza.name="{stanza.name}"')
            # Create a sub-dictionary for the current stanza name if it doesn't exist
            if stanza.name not in ta_trackme_cribl_conf:
                ta_trackme_cribl_conf[stanza.name] = {}

            # Store key-value pairs from the stanza content in the corresponding sub-dictionary
            for stanzakey, stanzavalue in stanza.content.items():
                logging.debug(
                    f'ta_trackme_cribl_conf, Processing stanzakey="{stanzakey}", stanzavalue="{stanzavalue}"'
                )
                ta_trackme_cribl_conf[stanza.name][stanzakey] = stanzavalue

        # set logging_level
        logginglevel = logging.getLevelName(
            ta_trackme_cribl_conf["logging"]["loglevel"]
        )
        log.setLevel(logginglevel)

        # gen record
        record = {
            "user": request_info.user,
            "server_rest_uri": request_info.server_rest_uri,
            "server_rest_host": request_info.server_rest_host,
            "server_rest_port": request_info.server_rest_port,
            "server_hostname": request_info.server_hostname,
            "server_servername": request_info.server_servername,
            "connection_src_ip": request_info.connection_src_ip,
            "connection_listening_port": request_info.connection_listening_port,
            "logging_level": ta_trackme_cribl_conf["logging"]["loglevel"],
            "ta_trackme_cribl_conf": ta_trackme_cribl_conf,
        }

        return {"payload": record, "status": 200}

    # Test remote connectivity prior to the creation of a Cribl account
    def post_test_cribl_connectivity(self, request_info, **kwargs):
        describe = False

        # Retrieve from data
        try:
            resp_dict = json.loads(str(request_info.raw_args["payload"]))
        except Exception as e:
            resp_dict = None

        if resp_dict is not None:
            try:
                describe = resp_dict["describe"]
                if describe in ("true", "True"):
                    describe = True
            except Exception as e:
                describe = False
                cribl_deployment_type = resp_dict.get("cribl_deployment_type", "cloud")
                cribl_onprem_leader_url = resp_dict.get("cribl_onprem_leader_url", None)
                cribl_client_id = resp_dict.get("cribl_client_id", None)
                cribl_client_secret = resp_dict.get("cribl_client_secret", None)
        else:
            # body is not required in this endpoint, if not submitted do not describe the usage
            describe = False

        # if describe is requested, show the usage
        if describe:
            response = {
                "describe": "This endpoint performs a connectivity check for Cribl API prior to the configuration of the account, it requires a POST call with the following options:",
                "resource_desc": "Run connectivity checks for Cribl API prior to the creation fo an account, this validates the configuration, network connectivity and authentication",
                "resource_spl_example": "| cribl mode=post url=\"/services/cribl/v1/test_cribl_connectivity\" body=\"{'cribl_deployment_type': 'cloud', 'cribl_client_id': '<client_id>', 'cribl_api_password': '<cribl_client_secret>'}\"",
                "options": [
                    {
                        "cribl_deployment_type": "The Cribl deployment type, valid options: cloud | onprem",
                        "cribl_onprem_leader_url": "For on-premise, The Cribl leader url in the form: https://<url>:<port>",
                        "cribl_client_id": "The usernane if using on-premise, client_id if using Cloud",
                        "cribl_client_secret": "The password if using on-premise, client_secret if using Cloud",
                    }
                ],
            }
            return {"payload": response, "status": 200}

        # set loglevel
        loglevel = cribl_getloglevel(
            request_info.system_authtoken, request_info.server_rest_port
        )
        log.setLevel(logging.getLevelName(loglevel))

        try:
            connection_info = {
                "cribl_deployment_type": cribl_deployment_type,
                "cribl_onprem_leader_url": cribl_onprem_leader_url,
                "cribl_client_id": cribl_client_id,
                "cribl_client_secret": cribl_client_secret,
            }
            response = cribl_test_remote_connectivity(connection_info)
            return {"payload": response, "status": 200}

        # note: the exception is returned as a JSON object
        except Exception as e:
            return {"payload": str(e), "status": 500}
