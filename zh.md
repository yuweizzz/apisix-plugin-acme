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

## 描述

`acme` 插件可以定时检查 SSL 证书资源，并通过 ACME 协议进行自动更新。

## 启用插件

这个插件是默认禁用的，通过修改配置文件 `./conf/config.yaml` 来启用它：

```yaml
plugins:
  - ...
  - acme
```

修改配置文件之后，重启 APISIX 或者通过插件热加载接口来使配置生效：

> [!TIP]
> 您可以这样从 `config.yaml` 中获取 `admin_key` 并存入环境变量：
>
> ```bash
> admin_key=$(yq '.deployment.admin.admin_key[0].key' conf/config.yaml | sed 's/"//g')
> curl http://127.0.0.1:9180/apisix/admin/plugins/reload -H "X-API-KEY: $admin_key" -X PUT
> ```

## 配置

使用 acme 插件必须先进行插件配置，你可以通过端点 apisix/admin/plugin_metadata/acme 进行插件配置，例如：

```bash
admin_key=$(yq '.deployment.admin.admin_key[0].key' conf/config.yaml | sed 's/"//g')
curl localhost:9180/apisix/admin/plugin_metadata/acme -H "X-API-KEY: ${admin_key}" -X PUT -d '
{
    "account_email": "account@email.com"
}'
```

然后你可以通过 Control API 进行 ACME 账户初始化，然后将账户信息更新到插件配置中：

```bash
curl localhost:9090/v1/plugin/acme/init -X POST | curl localhost:9180/apisix/admin/plugin_metadata/acme -H "X-API-KEY: ${admin_key}" -X PUT -d @-
```

你也可以自行创建 ACME 账户，然后通过 Admin API 更新到插件配置中。

参考以下的插件配置字段：

| 名称                 | 类型    | 必选项 | 默认值  | 有效值 | 描述                                                                        |
|----------------------|--------|--------|--------|--------|-----------------------------------------------------------------------------|
| api_uri              | string | 否     | "https://acme-v02.api.letsencrypt.org/directory" | | 由证书颁发机构提供的 ACME 服务器的目录 URL |
| account_email        | string | 是     | ""     | | 用于 ACME 账户注册的 contact 邮箱 |
| account_key          | string | 否     | ""     | | 用于 ACME 请求过程中的账户私钥，需要使用 PEM 格式 |
| account_kid          | string | 否     | ""     | | 注册完成后的 ACME 账户 URL 地址 |
| eab_kid              | string | 否     | ""     | | 由支持 External Account Binding 的证书颁发机构提供的 Key ID |
| eab_hmac_key         | string | 否     | ""     | | 由支持 External Account Binding 的证书颁发机构提供的 HMAC 密钥，和 Key ID 是成对存在的 |
| renew_threshold      | number | 否     | 604800 | | 触发证书更新的阈值，默认值是 7 天，即距离证书过期 7 天的时候进行更新 |
| renew_check_interval | number | 否     | 21600  | | 内部 SSL 资源检查频率，默认值是 6 小时，即每过 6 个小时，检查一次所有的 SSL 资源的过期时间 |

> [!NOTE]
> 这里的必选项指的是更新插件配置时的必选项，为了保证插件正常工作，原则上除了没有 EAB 要求的证书颁发机构可以不填 `eab_kid` 和 `eab_hmac_key` 之外，所有字段都需要填写。

为了支持 http-01 验证方式，你需要配置一个公共路由来暴露 ACME 的质询端点，从而使证书颁发机构能够访问到 APISIX ：

```bash
curl -XPUT 'http://localhost:9180/apisix/admin/routes/1' -H "X-API-KEY: ${admin_key}" -H 'Content-Type: application/json' -d '{
    "uri": "/.well-known/acme-challenge/*",
    "plugins": {
        "public-api": {}
    }
}'
```

## 属性

插件属性存储在 SSL 资源的 `acme` 字段中：

| 名称              | 类型    | 必选项 | 默认值     | 有效值                | 描述                                 |
|-------------------|---------|----|-----------|-----------------------|-------------------------------------|
| enabled           | boolean | 否 | False     |                       | 是否为当前 SSL 资源启用 ACME 自动更新 |
| challenge_handler | string  | 否 | "http-01" | ["http-01", "dns-01"] | 域名所有权验证方式 |
| dns_provider      | object  | 否 |           |                       | 使用 dns-01 验证时的 DNS 服务商配置 |

`acme` 字段中的 `dns_provider` 子字段属性：

| 名称      | 类型   | 必选项 | 默认值       | 有效值                                 | 描述                                               |
|----------|--------|-------|--------------|----------------------------------------|----------------------------------------------------|
| provider | string | 否 | "cloudflare" | ["cloudflare", "dnspod-intl", "dynv6"] | 对应的 DNS 服务商名称 |
| secret   | string | 是 | ""           |                                        | 访问 DNS 服务商 API 的身份凭证，比如 Token 或 API Key |

## 使用示例

首先您应该创建一个 SSL 资源，如下示例中：

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

这里不做额外配置，默认使用 http-01 验证方式，然后你需要通过 Control API 启动 acme 插件的定时任务：

```bash
curl localhost:9090/v1/plugin/acme/start -X POST
```

如果使用了通配符证书，必须使用 dns-01 验证方式，参考如下示例：

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

在正确设置了插件配置和公共路由的情况下，如果你的证书在更新阈值内，会自动触发更新，签发的证书名称会和原有证书保持一致。

如果你需要停止 acme 插件的定时任务，可以通过 Control API 进行：

```bash
curl localhost:9090/v1/plugin/acme/stop -X POST
```

## 删除插件

在删除插件之前，请先通过 Control API 停止 acme 插件的定时任务，并且需要确保所有的 SSL 资源都已经移除 `acme` 字段，可以通过以下命令实现对单个 SSL 资源的对应字段移除：

```shell
curl localhost:9180/apisix/admin/ssls/1 \
-H "X-API-KEY: $admin_key" -X PATCH -d '
{
    "acme": null
}'
```

通过修改配置文件 `./conf/config.yaml` 来禁用它：

```yaml
plugins:
  - ...
  # - acme
```

修改配置文件之后，重启 APISIX 或者通过插件热加载接口来使配置生效：

```shell
curl http://127.0.0.1:9180/apisix/admin/plugins/reload -H "X-API-KEY: $admin_key" -X PUT
```
