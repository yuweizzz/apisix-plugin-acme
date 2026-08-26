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


local ngx_timer_every = ngx.timer.every

local require = require
local core = require("apisix.core")
local plugin = require("apisix.plugin")
local acme = require("resty.acme.client")

local plugin_name = "acme"

local metadata_schema = {
    type = "object",
    properties = {
        api_uri = {
            type = "string",
            minLength = 1,
            default = "https://acme-v02.api.letsencrypt.org/directory",
        },
        account_email = {
            type = "string",
            minLength = 1,
        },
        account_key = {
            type = "string",
            minLength = 1,
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
    },
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
            challenge_handler = {
                type = "string",
                default = "http-01",
                enum = {"http-01", "dns-01"},
            },
        }
    }
end

function _M.destroy()
    core.schema.ssl.properties.acme = nil
end

return _M
