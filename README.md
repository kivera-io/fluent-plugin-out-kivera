# fluent-plugin-out-kivera, a plugin for [Fluentd](http://fluentd.org)

A generic [fluentd][1] output plugin for sending Kivera proxy logs to the Kivera log ingestion service.

## Configuration options

You can specify the path to a config.json file which can contain the following parameters:

*config.json*
```
{
    "client_id": "",
    "client_secret": "",
    "audience": "",
    "auth0_domain": "",
    "auth0_cert": "",
    "auth0_cert_file": ""
}
```

Note that parameter specified within the config_file will take precendence over parameters specified in your fluent.conf.
Also note that the auth0_cert parameter will take precedence over the auth0_cert_file parameter.

*fluent.conf*
```
<match *>
    @type kivera
    endpoint_url              http://localhost.local/api/
    config_file               /path/to/config_file.json
    client_id                 abc123
    client_secret             def456
    audience                  http://api.kivera.io
    auth0_domain              auth.nonp.kivera.io
    auth0_cert                -----BEGIN CERTIFICATE-----...
    auth0_cert_file           /path/to/auth0_cert_file
    ssl_no_verify             false  # default: false
    rate_limit_msec           100    # default: 0 = no rate limiting
    raise_on_error            false  # default: true
    recoverable_status_codes  503, 400 # default: 503
    custom_headers            {"token":"arbitrary"} # default: nil
    buffered                  true   # default: false. Switch non-buffered/buffered mode
    bulk_request              true  # default: true. Send events as application/x-ndjson
    compress_request          true  # default: false. Send compressed events
</match>
```

## Usage notes

If you'd like to retry failed requests, consider using [fluent-plugin-bufferize][3].
Or, specify appropriate `recoverable_status_codes` parameter.

To send events with bulk_request, you should specify `bulk_request` as `true`
Note that when this parameter as `true`, Fluentd always send events as `application/x-ndjson`.
Currently, `application/x-ndjson` is only supported MIME type for bulk_request.

----

Heavily based on [fluent-plugin-out-http][2]

  [1]: http://fluentd.org/
  [2]: https://github.com/fluent-plugins-nursery/fluent-plugin-out-http
  [3]: https://github.com/sabottenda/fluent-plugin-bufferize
