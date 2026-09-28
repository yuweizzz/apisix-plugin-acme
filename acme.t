#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
use t::APISIX 'no_plan';

repeat_each(1);
log_level('info');
no_root_location();
no_shuffle();

add_block_preprocessor(sub {
    my ($block) = @_;

    # setup default conf.yaml
    my $extra_yaml_config = $block->extra_yaml_config // <<_EOC_;
plugins:
  - acme
_EOC_

    $block->set_value("extra_yaml_config", $extra_yaml_config);

    if (!$block->request) {
        $block->set_value("request", "GET /t");
    }
});

run_tests;

__DATA__

=== TEST 1: disable acme plugin
--- extra_yaml_config
--- config
location /t {
    content_by_lua_block {
        local core = require("apisix.core")
        local t = require("lib.test_admin")

        local ssl_cert = t.read_file("t/certs/apisix.crt")
        local ssl_key =  t.read_file("t/certs/apisix.key")

        local data = {
            cert = ssl_cert,
            key = ssl_key,
            sni = "test.com",
            acme = {}
        }

        local code, body = t.test('/apisix/admin/ssls/1',
            ngx.HTTP_PUT,
            core.json.encode(data)
        )

        ngx.status = code
        ngx.print(body)
    }
}
--- error_code: 400
--- response_body
{"error_msg":"invalid configuration: additional properties forbidden, found acme"}



=== TEST 2: check schema when enabled acme plugin
--- config
location /t {
    content_by_lua_block {
        local core = require("apisix.core")
        local json = require("toolkit.json")

        for _, conf in ipairs({
            {},
            {enabled = true},
            {enabled = true, challenge_handler = "http-01"},
            {enabled = true, challenge_handler = "dns-01", dns_provider = { secret = "abcdef" }},
        }) do
            local ok, err = core.schema.check(core.schema.ssl.properties.acme, conf)
            if not ok then
                ngx.say(err)
                return
            end
            ngx.say(json.encode(conf))
        end
    }
}
--- response_body
{"challenge_handler":"http-01","enabled":false}
{"challenge_handler":"http-01","enabled":true}
{"challenge_handler":"http-01","enabled":true}
{"challenge_handler":"dns-01","dns_provider":{"provider":"cloudflare","secret":"abcdef"},"enabled":true}



=== TEST 3: ssl config without "acme" field when enabled acme plugin
--- config
location /t {
    content_by_lua_block {
        local core = require("apisix.core")
        local t = require("lib.test_admin")

        local ssl_cert = t.read_file("t/certs/apisix.crt")
        local ssl_key =  t.read_file("t/certs/apisix.key")

        local data = {
            cert = ssl_cert,
            key = ssl_key,
            sni = "test.com",
        }

        local code, body = t.test('/apisix/admin/ssls/1',
            ngx.HTTP_PUT,
            core.json.encode(data)
        )

        if code >= 300 then
            ngx.status = code
            ngx.say(body)
            return
        end

        ngx.say(body)
    }
}
--- response_body
passed



=== TEST 4: put acme metadata
--- config
location /t {
    content_by_lua_block {
        local t = require("lib.test_admin").test
        local code = t('/apisix/admin/plugin_metadata/acme',
            ngx.HTTP_PUT,
            [[{
                "account_email":"example@email.com"
            }]]
        )
        if code >= 300 then
            ngx.status = code
            return
        end
    }
}
--- error_code: 200



=== TEST 5: check acme metadata
--- config
location /t {
    content_by_lua_block {
        local core = require("apisix.core")
        local json = require("toolkit.json")
        local acme = require("apisix.plugins.acme")
        for _, conf in ipairs({
            {account_email = "example@email.com"},
        }) do
            local ok, err = core.schema.check(acme.metadata_schema, conf)
            if not ok then
                ngx.say(err)
                return
            end
            ngx.say(json.encode(conf))
        end
    }
}
--- response_body
{"account_email":"example@email.com","api_uri":"https://acme-v02.api.letsencrypt.org/directory","renew_check_interval":21600,"renew_threshold":604800}
