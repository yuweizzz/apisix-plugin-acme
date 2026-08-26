# apisix-plugin-acme

## config.yaml

```yaml
# add
nginx_config:
  http_configuration_snippet: 'lua_shared_dict acme 20m;'
# add
plugins:
- acme
```

## apisix-master-0.rockspec

```bash
luarocks install lua-resty-acme
```

## acme account key

```bash
# account key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out account.key

# plugin_metadata
admin_key=$(yq '.deployment.admin.admin_key[0].key' conf/config.yaml | sed 's/"//g')
curl http://127.0.0.1:9180/apisix/admin/plugin_metadata/acme -H "X-API-KEY: ${admin_key}" -X PUT -d '{}'
```
