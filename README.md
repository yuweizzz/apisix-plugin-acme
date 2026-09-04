# apisix-plugin-acme

## install

修改 config.yaml 文件。

```yaml
# config.yaml
# add
nginx_config:
  http_configuration_snippet: 'lua_shared_dict acme 20m;'
# add
plugins:
- acme
```

安装依赖。

```bash
luarocks install lua-resty-acme --tree deps
```

生成密钥。

```bash
# Create account_key 
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out account.key

# Create plugin metadata

# Use init api:
# 1. add account email
admin_key=$(yq '.deployment.admin.admin_key[0].key' conf/config.yaml | sed 's/"//g')
curl http://127.0.0.1:9180/apisix/admin/plugin_metadata/acme -H "X-API-KEY: ${admin_key}" -X PUT -d '{"account_email": "account@email.com"}'
# 2. init and update plugin metadata
curl localhost:9090/v1/plugin/acme/init -X POST | curl http://127.0.0.1:9180/apisix/admin/plugin_metadata/acme -H "X-API-KEY: ${admin_key}" -X PUT -d @-

# Or: PUT plugin metadata at once, not need to use init api
# curl http://127.0.0.1:9180/apisix/admin/plugin_metadata/acme -H "X-API-KEY: ${admin_key}" -X PUT -d @metadata.json
```
