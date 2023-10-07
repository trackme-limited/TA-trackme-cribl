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
import re
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
from cribl_libs import cribl_reqinfo


@Configuration(distributed=False)
class TrackMeRestHandler(GeneratingCommand):
    url = Option(
        doc="""
        **Syntax:** **The endpoint URL=****
        **Description:** Mandatory, the endpoint URL""",
        require=True,
        default=None,
        validate=validators.Match("url", r"^\/services\/cribl\/v\d*."),
    )

    mode = Option(
        doc="""
        **Syntax:** **The HTTP mode=****
        **Description:** Optional, the HTTP mode to be used for the REST API call""",
        require=False,
        default="get",
        validate=validators.Match("mode", r"^(?:get|post|delete)$"),
    )

    body = Option(
        doc="""
        **Syntax:** **The HTTP body data=****
        **Description:** Optional, the HTTP data to be used for the REST API call, optional for get and mandatory for post/delete calls""",
        require=False,
        default=None,
    )

    def generate(self, **kwargs):
        # Start performance counter
        start = time.time()

        # Get request info and set logging level
        reqinfo = cribl_reqinfo(
            self._metadata.searchinfo.session_key, self._metadata.searchinfo.splunkd_uri
        )
        log.setLevel(logging.getLevelName(reqinfo["logging_level"]))

        # Get the session key
        session_key = self._metadata.searchinfo.session_key

        # Build header and target
        header = f"Splunk {session_key}"
        target_url = f"{reqinfo['server_rest_uri']}/{self.url}"

        # Prepare the body data, if any
        if self.body:
            try:
                # Try parsing as standard JSON (with double quotes)
                json_obj = json.loads(self.body)
            except ValueError:
                # If it fails, try parsing with ast.literal_eval (supports single quotes)
                json_obj = literal_eval(self.body)

            json_data = json.dumps(json_obj, indent=1)
        else:
            json_data = None

        # Run http request
        headers = {"Authorization": header}
        if json_data:
            headers["Content-Type"] = "application/json"

        with requests.Session() as session:
            if self.mode == "get":
                response = session.get(
                    target_url, headers=headers, verify=False, data=json_data
                )
            elif self.mode == "post":
                response = session.post(
                    target_url, headers=headers, verify=False, data=json_data
                )
            elif self.mode == "delete":
                response = session.delete(
                    target_url, headers=headers, verify=False, data=json_data
                )

        # If response is an array containing multiple JSON objects, return as response.text
        if (
            re.search(r"^\[", response.text)
            and re.search(r"\}\,", response.text)
            and re.search(r"\]$", response.text)
        ):
            response_data = response.text
        else:
            try:
                response_data = response.json()
            except ValueError:
                # Response is not JSON, let's parse and make it a JSON answer
                response_data = {"response": response.text.replace('"', r"\"")}

        # Yield data
        data = {"_time": time.time(), "_raw": response_data}
        yield data
        logging.debug(response_data)
        logging.info("call terminated, response is logged in debug mode only")

        # Log the run time
        logging.info(
            f"trackme has terminated, run_time={round(time.time() - start, 3)}"
        )


dispatch(TrackMeRestHandler, sys.argv, sys.stdin, sys.stdout, __name__)
