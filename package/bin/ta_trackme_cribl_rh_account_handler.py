import import_declare_test
from splunktaucclib.rest_handler.admin_external import AdminExternalHandler
import json
import requests


class CustomRestHandlerCreateRemoteAccount(AdminExternalHandler):
    def __init__(self, *args, **kwargs):
        AdminExternalHandler.__init__(self, *args, **kwargs)

    def checkConnectivity(self):
        # set call
        header = {
            "Authorization": "Splunk %s" % self.getSessionKey(),
            "Content-Type": "application/json",
        }

        url = "%s/services/cribl/v1/test_cribl_connectivity" % self.handler._splunkd_uri
        data = {
            "cribl_deployment_type": self.payload.get("cribl_deployment_type"),
            "cribl_onprem_leader_url": self.payload.get("cribl_onprem_leader_url"),
            "cribl_client_id": self.payload.get("cribl_client_id"),
            "cribl_client_secret": self.payload.get("cribl_client_secret"),
            "cribl_ssl_verify": self.payload.get("cribl_ssl_verify"),
            "cribl_ssl_certificate_path": self.payload.get(
                "cribl_ssl_certificate_path"
            ),
        }

        # check connectivity, raise an exception if the connectivity check fails
        try:
            response = requests.post(
                url, headers=header, data=json.dumps(data, indent=1), verify=False
            )
            if response.status_code not in (200, 201, 204):
                msg = f'remote connectivity check has failed, response.status_code="{response.status_code}", response.text="{response.text}"'
                raise Exception(msg)
        except Exception as e:
            raise Exception(str(e))

    def handleList(self, confInfo):
        AdminExternalHandler.handleList(self, confInfo)

    def handleEdit(self, confInfo):
        self.checkConnectivity()
        AdminExternalHandler.handleEdit(self, confInfo)

    def handleCreate(self, confInfo):
        self.checkConnectivity()
        AdminExternalHandler.handleCreate(self, confInfo)

    def handleRemove(self, confInfo):
        AdminExternalHandler.handleRemove(self, confInfo)
