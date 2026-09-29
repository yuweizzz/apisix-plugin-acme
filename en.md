<!--
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
-->

## Description

The `acme` plugin can periodically check SSL certificate resources and automatically renew them using the ACME protocol.

## Enable Plugin

This Plugin is disabled by default. Modify the config file to enable the plugin:

```yaml title="./conf/config.yaml"
plugins:
  - ...
  - acme
```

After modifying the config file, reload APISIX or send a hot-loaded HTTP request through the Admin API to take effect:

> [!TIP]
> You can fetch the `admin_key` from `config.yaml` and save to an environment variable with the following command:
>
> ```bash
> admin_key=$(yq '.deployment.admin.admin_key[0].key' conf/config.yaml | sed 's/"//g')
> curl http://127.0.0.1:9180/apisix/admin/plugins/reload -H "X-API-KEY: $admin_key" -X PUT
> ```

## Configurations

You need to set up plugin metadata before using acme plugin, you can change this configuration of the Plugin through the endpoint `apisix/admin/plugin_metadata/acme`.

For example:

```bash
admin_key=$(yq '.deployment.admin.admin_key[0].key' conf/config.yaml | sed 's/"//g')
curl localhost:9180/apisix/admin/plugin_metadata/acme -H "X-API-KEY: ${admin_key}" -X PUT -d '
{
    "account_email": "account@email.com"
}'
```

After that, you can use the Control API to initialize the ACME account, and then update the account information to the plugin metadata:

```bash
curl localhost:9090/v1/plugin/acme/init -X POST | curl localhost:9180/apisix/admin/plugin_metadata/acme -H "X-API-KEY: ${admin_key}" -X PUT -d @-
```

Or you can create an ACME account yourself and then update to plugin metadata via the Admin API.

The `acme` plugin metadata fields:

| Name                 | Type   | Required | Default | Valid values | Description                                                                 |
|----------------------|--------|----------|---------|--------------|-----------------------------------------------------------------------------|
| api_uri              | string | false    | "https://acme-v02.api.letsencrypt.org/directory" | | Directory URL of the ACME server provided by the Certificate Authority |
| account_email        | string | true     | ""     | | Contact email address for ACME account registration |
| account_key          | string | false    | ""     | | Account private key using in ACME request process, must be in PEM format |
| account_kid          | string | false    | ""     | | ACME account URL after registration |
| eab_kid              | string | false    | ""     | | Key ID provided by the Certificate Authority that supports External Account Binding |
| eab_hmac_key         | string | false    | ""     | | HMAC key provided by the Certificate Authority that supports External Account Binding, exist as a pair with Key ID |
| renew_threshold      | number | false    | 604800 | | Threshold for triggering certificate renewal, the default value is 7 days, meaning renewal occurs 7 days before the certificate expires |
| renew_check_interval | number | false    | 21600  | | Internal SSL resource check frequency, the default value is 6 hours, meaning all the expiration dates of SSL resources will be checked every 6 hours |

> [!NOTE]
> The "Required fields" referred to here are those required when updating the plugin configuration. If you create an ACME account yourself, to ensure the plugin functions correctly, all fields must be filled, except the situation that the Certificate Authority does not require EAB, and the `eab_kid` and `eab_hmac_key` fields may be left blank.

To support the http-01 challenge, you need to configure a public route to expose the ACME challenge endpoint, allowing the Certificate Authority to access APISIX:

```bash
curl -XPUT 'http://localhost:9180/apisix/admin/routes/1' -H "X-API-KEY: ${admin_key}" -H 'Content-Type: application/json' -d '{
    "uri": "/.well-known/acme-challenge/*",
    "plugins": {
        "public-api": {}
    }
}'
```

## Attributes

The attributes of this plugin are stored in specific field `acme` within SSL Resource.

| Name                 | Type   | Required | Default | Valid values | Description                             |
|-------------------|---------|----|-----------|-----------------------|-------------------------------------|
| enabled           | boolean | false | false     |                       | Enabled ACME automatic renewal for the current SSL resource |
| challenge_handler | string  | false | "http-01" | ["http-01", "dns-01"] | Domain Ownership challenge Methods |
| dns_provider      | object  | false |           |                       | DNS Provider Configuration for dns-01 challenge |

The attributes of `dns_provider`, which is the subfield of `acme`：

| Name                 | Type   | Required | Default | Valid values | Description                                                                 |
|----------|--------|-------|--------------|----------------------------------------|----------------------------------------------------|
| provider | string | false | "cloudflare" | ["cloudflare", "dnspod-intl", "dynv6"] | Name of the DNS provider |
| secret   | string | true | ""           |                                        | Authentication credentials for accessing the DNS provider's API, such as a token or API key |

## Example usage

You can create an SSL Resource as such:

```shell
curl localhost:9180/apisix/admin/ssls/1 \
-H "X-API-KEY: $admin_key" -X PUT -d '
{
    "cert" : "'"$(cat server.crt)"'",
    "key": "'"$(cat server.key)"'",
    "snis": ["test.com"],
    "acme": {
        "enabled": true
    }
}'
```

there are no additional configuration here, the http-01 challenge is used by default. You then need to start the acme plugin's scheduled task via the Control API:

```bash
curl localhost:9090/v1/plugin/acme/start -X POST
```

And if you are using wildcard certificate, you must configure the dns-01 challenge, such as:

```shell
curl localhost:9180/apisix/admin/ssls/2 \
-H "X-API-KEY: $admin_key" -X PUT -d '
{
    "cert" : "'"$(cat server.crt)"'",
    "key": "'"$(cat server.key)"'",
    "snis": ["*.test.com"],
    "acme": {
        "enabled": true,
        "challenge_handler": "dns-01",
        "dns_provider": {
            "provider": "cloudflare",
            "secret": "your-cloudflare-api-token"
        }
    }
}'
```

When provided the plugin configuration and public routes are correctly set up, an automatic renewal will be triggered if your certificate falls within the renewal threshold; the issued certificate will retain the same name as the original.

If you need to stop the scheduled tasks for the acme plugin, you can do so via the Control API:

```bash
curl localhost:9090/v1/plugin/acme/stop -X POST
```

## Delete Plugin

Before deleting the plugin, make sure the the scheduled tasks for the acme plugin is stopped, and all your SSL Resource no longer contain `acme` field anymore.

To stop the scheduled tasks for the acme plugin, you can make a request as shown below:

```bash
curl localhost:9090/v1/plugin/acme/stop -X POST
```

To remove the `acme` field from your SSL Resource, you can make a request as shown below:

```shell
curl http://127.0.0.1:9180/apisix/admin/ssls/1 \
-H "X-API-KEY: $admin_key" -X PATCH -d '
{
    "acme": null
}'
```

Modify the config file `./conf/config.yaml` to disable the plugin:

```yaml title="./conf/config.yaml"
plugins:
  - ...
  # - acme
```

After modifying the config file, reload APISIX or send a hot-loaded HTTP request through the Admin API to take effect:

```shell
curl http://127.0.0.1:9180/apisix/admin/plugins/reload -H "X-API-KEY: $admin_key" -X PUT
```
