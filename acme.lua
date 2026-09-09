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


local require = require

local ngx_process = require("ngx.process")
local ngx_timer_every = ngx.timer.every

local acme = require("resty.acme.client")
local util = require("resty.acme.util")
local x509 = require("resty.openssl.x509")

local core = require("apisix.core")
local plugin = require("apisix.plugin")


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
            acme_enabled = {
                type = "boolean",
                default = false,
            },
            challenge_handler = {
                type = "string",
                default = "http-01",
                enum = {"http-01", "dns-01"},
            },
        }
    }

    acme_cache:set('stopped', 'true')
end


local function init_account()
    local metadata = plugin.plugin_metadata(plugin_name)
    if not metadata or not metadata.value then
        return 400, { error_msg = "plugin metadata for acme is required" }
    end

    local config = metadata.value
    if not config.account_key then
        config.account_key = util.create_pkey(4096, "RSA")
    end
    if not config.account_kid then
        -- storage in shm
        local client, err = acme.new(config)
        if not client then
            return 500, { error_msg = err }
        end
    	err = client:init()
        if err then
            return 500, { error_msg = err }
        end
        config.account_kid, err = client:new_account()
        if err then
            return 500, { error_msg = err }
        end
        return 200, config
    end
    return 304, { error_msg = "plugin metadata for acme already initialized" }
end

local function order_certificate()
end

local function renew_check(premature, config)
    if premature or acme_cache:get('stopped') == 'true' then
        return
    end

    local ssl = require("apisix.admin.ssl")
    -- secret key cleared bypass
    local resource_name = ssl.name
    ssl.name = 'ssl'
    local _, ssls_resource = ssl:get()
    if ssls_resource.count <= 0 then
        core.log.debug("no ssl resource found")
        return
    end
    -- recover for patch
    ssl.name = resource_name

    local ssls = ssls_resource.list
    for _, item in ipairs(ssls) do
        if not item.value.acme or not item.value.acme.acme_enabled then
            core.log.debug(item.key, " is not managed by acme plugin, pass it")
            return
        end
        local cert = x509.new(item.value.cert)
        local now = ngx.now()
        local _, not_after = cert:get_lifetime()
        core.log.debug("cert renew check for: ", item.key, ", not after: ", os.date("%Y-%m-%d %H:%M:%S GMT", not_after))
        if not_after - now < config.renew_threshold then
            local new_cert, err = order_certificate(item.value.key, item.value.cert)
            if err then
                core.log.error("failed to renew cert: ", item.key, ", error: ", err)
            end
            local _, err = ssls_resource:patch(item.value.id, { cert = new_cert })
            if err then
                core.log.error("failed to patch resource: ", item.key, ", error: ", err)
            end
            core.log.info("resource: ", item.key, " renewed")
        end
    end
end

local function start_watch()
    local metadata = plugin.plugin_metadata(plugin_name)
    if not metadata or not metadata.value then
        return 400, { error_msg = "plugin metadata for acme is required" }
    end

    local config = metadata.value
    if not config.account_kid then
        return 400, { error_msg = "plugin metadata for acme is not initialized" }
    end

    _, err = ngx.timer.every(config.renew_check_interval, renew_check, config)
    if not err then
        acme_cache:set('stopped', 'false')
    end
end

local function stop_watch()
    acme_cache:set('stopped', 'true')
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


function _M.destroy()
    core.schema.ssl.properties.acme = nil
end

return _M
