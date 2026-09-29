--
-- Licensed to the Apache Software Foundation (ASF) under one
-- or more contributor license agreements.  See the NOTICE file
-- distributed with this work for additional information
-- regarding copyright ownership.  The ASF licenses this file
-- to you under the Apache License, Version 2.0 (the
-- "License"); you may not use this file except in compliance
-- with the License.  You may obtain a copy of the License at
--
--   http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing,
-- software distributed under the License is distributed on an
-- "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
-- KIND, either express or implied.  See the License for the
-- specific language governing permissions and limitations
-- under the License.
--


local pairs   = pairs
local ipairs  = ipairs
local table   = table
local unpack  = unpack
local ngx     = ngx
local os      = os
local require = require

local acme = require("resty.acme.client")
local util = require("resty.acme.util")
local x509 = require("resty.openssl.x509")

local core = require("apisix.core")
local plugin = require("apisix.plugin")
local ssl = require("apisix.admin.ssl")
local apisix_ssl = require("apisix.ssl")

-- same with lua-resty-acme default storage name
local plugin_name = "acme"
local acme_cache = ngx.shared[plugin_name]

local metadata_schema = {
    type = "object",
    properties = {
        api_uri = {
            type = "string",
            default = "https://acme-v02.api.letsencrypt.org/directory",
        },
        account_email = {
            type = "string",
        },
        account_key = {
            type = "string",
        },
        account_kid = {
            type = "string",
        },
        eab_kid = {
            type = "string",
        },
        eab_hmac_key = {
            type = "string",
        },
        renew_threshold = {
            type = "number",
            default = 7 * 86400,
            minimum = 86400,
        },
        renew_check_interval = {
            type = "number",
            default = 6 * 3600,
            minimum = 3600,
        },
    },
    required = {"account_email"},
}

local plugin_schema = {
    type = "object",
    properties = {},
}

local _M = {
    version = 0.3,
    priority = -45,
    name = plugin_name,
    schema = plugin_schema,
    metadata_schema = metadata_schema,
}


function _M.check_schema(conf, schema_type)
    if schema_type == core.schema.TYPE_METADATA then
        return core.schema.check(metadata_schema, conf)
    end
    return core.schema.check(plugin_schema, conf)
end


function _M.init()
    if core.schema.ssl.properties.gm ~= nil then
        core.log.error("acme plugin should not run with gm plugin")
    end

    if core.schema.ssl.properties.acme ~= nil then
        core.log.error("field 'acme' is occupied")
    end

    core.schema.ssl.properties.acme = {
        type = "object",
        properties = {
            enabled = {
                type = "boolean",
                default = false,
            },
            challenge_handler = {
                type = "string",
                default = "http-01",
                enum = { "http-01", "dns-01" },
            },
            dns_provider = {
                type = "object",
                properties = {
                    provider = {
                        type = "string",
                        default = "cloudflare",
                        -- provided by lua-resty-acme
                        enum = { "cloudflare", "dnspod-intl", "dynv6" },
                    },
                    secret = {
                        type = "string",
                    },
                },
                required = { "secret" },
            }
        }
    }

    acme_cache:set("stopped", "true")
end


local function renew_certificate(metadata, acme_config, key, cert_ref)
    -- check acme_config
    if acme_config.challenge_handler == "dns-01"
      and not acme_config.dns_provider
    then
        return nil, "dns_provider is required for dns-01 challenge"
    end

    local sn_obj = cert_ref:get_subject_name()
    local san_obj = cert_ref:get_subject_alt_name()
    local domain_list = {}
    for _, obj in pairs(san_obj) do
        table.insert(domain_list, obj)
    end
    core.log.debug("Raw SAN: ", core.json.delay_encode(domain_list))

    local cn_obj, _, err = sn_obj:find("CN")
    if err then
        return nil, "find CN failed: " .. err
    end
    local cn = cn_obj.blob
    -- make sure CN same with raw cert
    if domain_list[1] ~= cn then
        local domain = domain_list[1]
        domain_list[1] = cn
        table.insert(domain_list, domain)
    end
    core.log.debug("Renewed SAN: ", core.json.delay_encode(domain_list))

    metadata.enabled_challenge_handlers = { acme_config.challenge_handler }
    if acme_config.dns_provider then
        metadata.dns_provider_accounts = {
            {
                name = acme_config.dns_provider.provider,
                provider = acme_config.dns_provider.provider,
                secret = acme_config.dns_provider.secret,
                domains = domain_list,
            },
        }
    end
    local client, err = acme.new(metadata)
    if not client then
        return nil, err
    end
    err = client:init()
    if err then
        return nil, err
    end

    local new_cert, err = client:order_certificate(key, unpack(domain_list))
    if err then
        return nil, err
    end
    return new_cert
end


local function renew_check(premature, metadata)
    if premature or acme_cache:get("stopped") == "true" then
        return
    end

    -- get ssl resource, and bypass secret key clear
    local resource_name = ssl.name
    ssl.name = 'ssl'
    local _, ssls_resource = ssl:get()
    if ssls_resource.count <= 0 then
        core.log.debug("no ssl resource found")
        return
    end
    -- recover for patch ssl resource
    ssl.name = resource_name

    local ssls = ssls_resource.list
    for _, item in ipairs(ssls) do
        if not item.value.acme or not item.value.acme.enabled then
            core.log.debug(item.key, " is not managed by acme plugin, pass it")
            goto continue
        end
        local acme_config = item.value.acme
        local cert = x509.new(item.value.cert)
        local now = ngx.now()
        local _, not_after = cert:get_lifetime()
        core.log.debug(
          "cert renew check for: ", item.key, ", not after: ",
          os.date("%Y-%m-%d %H:%M:%S GMT", not_after)
        )
        if not_after - now < metadata.renew_threshold then
            local raw_key = apisix_ssl.aes_decrypt_pkey(item.value.key)
            local new_cert, err = renew_certificate(
              metadata, acme_config, raw_key, cert
            )
            if err then
                core.log.error(
                  "failed to renew cert: ", item.key, 
                  ", error: ", err
                )
            end
            local code, body = ssl:patch(item.value.id, { cert = new_cert })
            if code ~= 200 then
                core.log.error(
                  "failed to patch resource: ", item.key,
                  ", return: ", core.json.delay_encode(body)
                )
            end
            core.log.info("resource: ", item.key, " renewed")
        end
::continue::
    end
end


local function init_account()
    local metadata = plugin.plugin_metadata(plugin_name)
    if not metadata or not metadata.value then
        return 400, { error_msg = "plugin metadata for acme is required" }
    end

    local metadata_config = metadata.value
    if metadata_config.account_kid then
        return 200, { 
          error_msg = "plugin metadata for acme already initialized, do nothing"
        }
    end
    if not metadata_config.account_key then
        metadata_config.account_key = util.create_pkey(4096, "RSA")
    end
    -- storage in shm: 
    -- default_config = { 
    --  storage_adapter = "shm", 
    --  storage_config = { shm_name = "acme"}
    --  ...
    -- }
    local client, err = acme.new(metadata_config)
    if not client then
        return 500, { error_msg = err }
    end
    err = client:init()
    if err then
        return 500, { error_msg = err }
    end
    metadata_config.account_kid, err = client:new_account()
    if err then
        return 500, { error_msg = err }
    end
    return 200, metadata_config
end


local function start_watch()
    local value, err = acme_cache:get("stopped")
    if err then
        return 500, { error_msg = err }
    end
    if value == "false" then
        return 200, { msg = "acme timer is already running, do nothing" }
    end
    local metadata = plugin.plugin_metadata(plugin_name)
    if not metadata or not metadata.value then
        return 400, { error_msg = "plugin metadata for acme is required" }
    end

    local metadata_config = metadata.value
    if not metadata_config.account_kid then
        return 400, {
          error_msg = "plugin metadata for acme is not initialized"
        }
    end

    local _, err = ngx.timer.every(
      metadata_config.renew_check_interval, renew_check, metadata_config
    )
    if not err then
        acme_cache:set("stopped", "false")
        return 200, { msg = "acme timer now started" }
    end
    return 500, { error_msg = err }
end


local function stop_watch()
    local value, err = acme_cache:get("stopped")
    if err then
        return 500, { error_msg = err }
    end
    if value == "true" then
        return 200, { msg = "acme timer is already stopped, do nothing" }
    end
    acme_cache:set("stopped", "true")
    return 200, { msg = "acme timer now stopped" }
end


-- lua-resty-acme/lib/resty/acme/challenge/http-01.lua
local function serve_http_challenge()
    local captures, err = ngx.re.match(
      ngx.var.request_uri, [[/\.well-known/acme-challenge/(.+)]], "jo"
    )

    if err then
        core.response.exit(
          400, { 
            error_msg = "error extracting token from request_uri: " .. err 
          }
        )
    end

    if not captures or not captures[1] then
        core.response.exit(
          400, {
            error_msg = "error extracting token from request_uri: no captures"
          }
        )
    end

    local token = captures[1]
    -- token (required, string):  A random value that uniquely identifies
    -- the challenge.  This value MUST have at least 128 bits of entropy.
    -- It MUST NOT contain any characters outside the base64url alphabet
    -- and MUST NOT include base64 padding characters ("=").
    -- 128/6 = 21.333, no Padding = 22, Padding = 24
    if #token <= 21 then
        core.response.exit(400, { error_msg = "illegal token" })
    end
    core.log.debug("http-01 challenge token: ", token)
    local value, err = acme_cache:get(token .. "#http-01")
    if not value then
        core.response.exit(
          404, {
            error_msg = "no corresponding response found for " .. token
          }
        )
    end

    core.response.exit(200, value)
end


function _M.control_api()
    return {
        {
            methods = {"POST"},
            uris = {"/v1/plugin/acme/init"},
            handler = init_account,
        },
        {
            methods = {"POST"},
            uris = {"/v1/plugin/acme/start"},
            handler = start_watch,
        },
        {
            methods = {"POST"},
            uris = {"/v1/plugin/acme/stop"},
            handler = stop_watch,
        },
    }
end


function _M.api()
    return {
        {
            methods = {"GET"},
            uri = "/.well-known/acme-challenge/*",
            handler = serve_http_challenge,
        }
    }
end


function _M.destroy()
    core.schema.ssl.properties.acme = nil
end


return _M
