import import_declare_test

from splunktaucclib.rest_handler.endpoint import (
    field,
    validator,
    RestModel,
    SingleModel,
)
from splunktaucclib.rest_handler import admin_external, util
from ta_trackme_cribl_rh_account_handler import CustomRestHandlerCreateRemoteAccount
import logging

util.remove_http_proxy_env_vars()


fields = [
    field.RestField(
        "cribl_deployment_type",
        required=True,
        encrypted=False,
        default="cloud",
        validator=None,
    ),
    field.RestField(
        "cribl_cloud_organization_id",
        required=False,
        encrypted=False,
        default=None,
        validator=None,
    ),
    field.RestField(
        "cribl_url", required=False, encrypted=False, default=None, validator=None
    ),
    field.RestField(
        "cribl_client_id", required=True, encrypted=False, default=None, validator=None
    ),
    field.RestField(
        "cribl_client_secret",
        required=True,
        encrypted=True,
        default=None,
        validator=None,
    ),
    field.RestField(
        "rbac_roles",
        required=True,
        encrypted=False,
        default="admin,sc_admin,trackme_user,trackme_power,trackme_admin",
        validator=None,
    ),
]
model = RestModel(fields, name=None)


endpoint = SingleModel("ta_trackme_cribl_account", model, config_name="account")


if __name__ == "__main__":
    logging.getLogger().addHandler(logging.NullHandler())
    admin_external.handle(
        endpoint,
        handler=CustomRestHandlerCreateRemoteAccount,
    )
