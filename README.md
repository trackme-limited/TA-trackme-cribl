# TA-trackme-cribl: Cribl API integration for TrackMe

## Introduction

**This application provides API integration between Splunk and Cribl API:**

- Configure one or more Cribl API targets (account)
- The Cribl target can be an on-premise Cribl deployment, or Cribl Cloud
- Access and perform API calls to Cribl in pure Splunk SPL via the cribl builtin command
- Run pre-defined builtin functions to retrieve metrics for complex actions (example: get pipelines metrics), this allows charting realtime metrics in Splunk from the Cribl API
- Roles Based Access Control and least privilege approach

## License

**This application is licensed upon the TrackMe EULA:**

- https://docs.trackme-solutions.com/license.html

## Terms & Conditions

**Our terms and conditions can be found at the following address:**

- https://docs.trackme-solutions.com/terms_and_conditions.html

## Support

**Support conditions can be found at the following address:**

- https://docs.trackme-solutions.com/support.html

## Requirements

### Applications dependencies

This application has no dependencies regarding other Splunk applications.

### Network requirements

The Splunk Search Head where this application is deployed needs to able to reach the Cribl URL target on the associated port. (typically HTTPs over 443)

## Installation & deployment matrix

**Install this Splunk application on the following target:**

- Search Head(s), standalone or Search Head Cluster

## Configuration

**Once deployed, access the Configuration UI and create a first Cribl API account:**

| Parameter                       | Description                                                                                                   |
|---------------------------------|---------------------------------------------------------------------------------------------------------------|
| Name                            | Enter a unique name for this account. (default: cribl)                                                        |
| Cribl deployment type           | The type of Cribl deployment, Cloud or on-premise                                                             |
| cribl_cloud_organization_id     | If Cloud, specify the organization ID                                                                         |
| cribl_onprem_leader_url         | If on-premise, specify the leader URL in the format `https://<hostname>:<port>`                               |
| cribl_client_id                 | If on-premise, the username for the API connection, if using Cloud, the client_id.                            |
| cribl_client_secret             | If on-premise, the password for the API connection, if using Cloud, the client_secret.                        |
| rbac_roles                      | A comma separated list of Splunk roles a user must be a member of to be allowed to used this account, the role must be a true membership  |

**When creating the Account, the application will automatically attempt to access and authenticate against the Cribl API, if there are any failures, the UI show refuse the account creation and will return the exception.**

*You can also test the connectivity prior to the configuration of the account, in fact the UI calls this same endpoint to verify the connectivity for the account configuration:*

*Cribl Cloud example:*

    | cribl mode=post url="/services/cribl/v1/test_cribl_connectivity" body="{'cribl_deployment_type': 'cloud', 'cribl_client_id': '<redacted_client_id>', 'cribl_client_secret': '<redacted_client_secret>'}"

## Capabilities & Roles Based Access Control

### Capabilities & builtin roles

This application implements a least privilege approach, this means you do not require high privilege capabilities to be able to use the application and the underneath secrets, instead a capability can be added to your roles, or you can inherit from the builtin roles:

- capability: ``criblapi``
- builtin roles: ``cribl_api``

### Roles Based Access Control

On a per Cribl account basis, you can define the list of Splunk roles a user must be a member, this setting is defined at the level of the account:

- ``rbac_roles``, defaults to: admin,sc_admin,trackme_user,trackme_power,trackme_admin

This is a true membership, the user must be a member of the roles. (not inheriting one of these roles)

## Logs & Troubleshooting

### Internal REST API

The Application implements an API for its internal processing, logs are available at:

    index=_internal sourcetype="cribl:rest_api"

### Custom command

The Application provides a builtin custom command ``cribl`` allowing to interact with the Cribl API, logs can be found here:

    index=_internal sourcetype="cribl:custom_commands:cribl" 

## Usage

### Cribl API interactions

**The following command sheet shows various useful usage to interact with the Cribl API:**

#### Get workers count & information

    | cribl account=cribl mode=get url="/api/v1/master/groups?fields=workerCount&product=stream" | spath

#### Get extended workers info & stats

    | cribl account=cribl mode=get url="/api/v1/master/workers?filterExp=info.cribl.distMode%3D%3D%22worker%22" | spath

#### Get worker count

    | cribl account=cribl mode=get url="/api/v1/master/summary/workers?filterExp=info.cribl.distMode%3D%3D%22worker%22" | spath

#### Get groups

    | cribl account=cribl mode=get url="/api/v1/master/groups" | spath

#### Get groups (Cribl Stream only)

    | cribl account=cribl mode=get url="/api/v1/master/groups?product=stream" | spath

#### Get groups (only stream)

    | cribl account=cribl mode=get url="/api/v1/master/groups?product=stream" | spath

#### Get inputs

    | cribl account=cribl mode=get url="/api/v1/m/default/system/inputs" | spath

#### Get outputs

    | cribl account=cribl mode=get url="/api/v1/m/default/system/outputs" | spath

#### Get routes

    | cribl account=cribl mode=get url="/api/v1/m/default/routes" | spath

#### Get packs

    | cribl account=cribl mode=get url="/api/v1/m/default/packs" | spath

#### Get system metrics

    | cribl account=cribl mode=post url="/api/v1/system/metrics/query" cribl_function="get_global_metrics"

#### Get destination metrics

    | cribl account=cribl mode=post url="/api/v1/system/metrics/query" cribl_function="get_destinations_metrics"

#### Get pipelines metrics

    | cribl account=cribl mode=post url="/api/v1/system/metrics/query" cribl_function="get_pipelines_metrics"

#### Get routes metrics

    | cribl account=cribl mode=post url="/api/v1/system/metrics/query" cribl_function="get_routes_metrics"

#### Get system messages (there can be nothing here)

    | cribl account=cribl mode=get url="/api/v1/system/messages" | spath

#### Get banner (there can be nothing here)

    | cribl account=cribl mode=get url="/api/v1/system/banners" | spath

#### Get recent actions

    | cribl account=cribl mode=get url="/api/v1/ui/recentActions" | spath

### Internal API

**The following sections shows internal API calls:**

#### Test connectivity to Cribl before creating an account

    | cribl mode=post url="/services/cribl/v1/test_cribl_connectivity" body="{'cribl_deployment_type': 'cloud', 'cribl_client_id': '<redacted_client_id>', 'cribl_client_secret': '<redacted_client_secret>'}"

#### Access the account (for least privileges access)

*This is used internally to access credentials with a least privileges approach.*

    | cribl mode=post url="/services/cribl/v1/get_account" body="{'account': 'cribl'}"
