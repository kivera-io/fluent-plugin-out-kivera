# fluent-plugin-out-kivera, a plugin for [Fluentd](http://fluentd.org)

A generic [fluentd][1] output plugin for sending logs to an HTTP endpoint.
<!-- Replace with GoCD build status
[![Build Status](https://travis-ci.org/fluent-plugins-nursery/fluent-plugin-out-http.svg?branch=master)](https://travis-ci.org/fluent-plugins-nursery/fluent-plugin-out-http) -->


## Configuration options

    <match *>
      @type kivera
      endpoint_url    http://localhost.local/api/
      proxy_credentials_file /path/to/proxy_credentials_file
      proxy_client_id 
      proxy_client_secret
      kivera_api      http://api.kivera.io
      kivera_auth0_domain http://auth.nonp.kivera.io
      kivera_auth0_cert_file /path/to/auth0_cert_file
      ssl_no_verify   false  # default: false
      rate_limit_msec 100    # default: 0 = no rate limiting
      raise_on_error  false  # default: true
      recoverable_status_codes 503, 400 # default: 503
      custom_headers  {"token":"arbitrary"} # default: nil
      buffered        true   # default: false. Switch non-buffered/buffered mode
      bulk_request    false  # default: false. Send events as application/x-ndjson
      compress_request true  # default: false. Send compressed events
    </match>

## Usage notes

If you'd like to retry failed requests, consider using [fluent-plugin-bufferize][3].
Or, specify appropriate `recoverable_status_codes` parameter.

To send events with bulk_request, you should specify `bulk_request` as `true`
Note that when this parameter as `true`, Fluentd always send events as `application/x-ndjson`.
Currently, `application/x-ndjson` is only supported MIME type for bulk_request.

----

Heavily based on [fluent-plugin-growthforecast][2]

  [1]: http://fluentd.org/
  [2]: https://github.com/tagomoris/fluent-plugin-growthforecast
  [3]: https://github.com/sabottenda/fluent-plugin-bufferize
