static_resources:
  listeners:
    - name: ingress_listener
      address:
        socket_address:
          address: 0.0.0.0
          port_value: 8080
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress_http
                codec_type: AUTO
                http2_protocol_options:
                  max_concurrent_streams: 1000
                  initial_stream_window_size: 1048576
                  initial_connection_window_size: 2097152
                common_http_protocol_options:
                  idle_timeout: 300s
                  headers_with_underscores_action: REJECT_REQUEST
                stream_idle_timeout: 120s
                request_timeout: 60s
                route_config:
                  name: local_route
                  virtual_hosts:
                    - name: media_api
                      domains: ["*"]
                      routes:
                        - match:
                            safe_regex:
                              google_re2: {}
                              regex: '^/auth/login(?:\?.*)?$'
                          route:
                            cluster: auth_api
                          typed_per_filter_config:
                            envoy.filters.http.ext_authz:
                              "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute
                              disabled: true
                        - match:
                            safe_regex:
                              google_re2: {}
                              regex: '^/auth/callback(?:\?.*)?$'
                          route:
                            cluster: auth_api
                          typed_per_filter_config:
                            envoy.filters.http.ext_authz:
                              "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute
                              disabled: true
                        - match:
                            safe_regex:
                              google_re2: {}
                              regex: '^/auth/session(?:\?.*)?$'
                          route:
                            cluster: auth_api
                          typed_per_filter_config:
                            envoy.filters.http.ext_authz:
                              "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute
                              disabled: true
                        - match:
                            safe_regex:
                              google_re2: {}
                              regex: '^/auth/logout(?:\?.*)?$'
                          route:
                            cluster: auth_api
                          typed_per_filter_config:
                            envoy.filters.http.ext_authz:
                              "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute
                              disabled: true
                        - match:
                            prefix: "/auth"
                          route:
                            cluster: auth_api
                        - match:
                            prefix: "/"
                          route:
                            cluster: main_api
                http_filters:
                  - name: envoy.filters.http.lua
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua
                      inline_code: |
                        function envoy_on_request(request_handle)
                          -- Strip internal identity header from external clients before authn/authz.
                          request_handle:headers():remove("x-jwt-payload")
                        end

                        function envoy_on_response(response_handle)
                          response_handle:headers():add("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'self';")
                          response_handle:headers():add("X-Content-Type-Options", "nosniff")
                          response_handle:headers():add("X-Frame-Options", "DENY")
                          response_handle:headers():add("Referrer-Policy", "strict-origin-when-cross-origin")
                        end

                  - name: envoy.filters.http.lua
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua
                      inline_code: |
                        local allowed = {
                          ["${CORS_ALLOWED_ORIGIN_PRIMARY}"] = true,
                          ["${CORS_ALLOWED_ORIGIN_SECONDARY}"] = true
                        }

                        local function trim(value)
                          return (value:gsub("^%s+", ""):gsub("%s+$", ""))
                        end

                        local function cookie_value(cookie_header, target_name)
                          if not cookie_header then
                            return nil
                          end

                          for cookie in string.gmatch(cookie_header, "([^;]+)") do
                            local pair = trim(cookie)
                            local separator = string.find(pair, "=", 1, true)
                            if separator then
                              local name = trim(string.sub(pair, 1, separator - 1))
                              local value = trim(string.sub(pair, separator + 1))
                              if string.len(value) >= 2 and string.sub(value, 1, 1) == "\"" and string.sub(value, -1, -1) == "\"" then
                                value = string.sub(value, 2, -2)
                              end
                              if name == target_name then
                                return value
                              end
                            end
                          end

                          return nil
                        end

                        function envoy_on_request(request_handle)
                          local method = request_handle:headers():get(":method")
                          if method == "OPTIONS" then
                            return
                          end

                          local sec_fetch_site = request_handle:headers():get("sec-fetch-site")
                          local sec_fetch_mode = request_handle:headers():get("sec-fetch-mode")
                          if sec_fetch_site == "cross-site" and sec_fetch_mode == "navigate" then
                            request_handle:respond({[":status"] = "403"}, "cross-site navigation blocked")
                            return
                          end

                          if method ~= "GET" and method ~= "HEAD" then
                            local origin = request_handle:headers():get("origin")
                            if not origin or not allowed[origin] then
                              request_handle:respond({[":status"] = "403"}, "invalid origin")
                              return
                            end

                            local csrf_header = request_handle:headers():get("x-csrf-token")
                            local cookie_header = request_handle:headers():get("cookie")
                            local csrf_cookie = cookie_value(cookie_header, "csrf-token")

                            if not csrf_header or not csrf_cookie or csrf_header ~= csrf_cookie then
                              request_handle:respond({[":status"] = "403"}, "csrf token mismatch")
                              return
                            end
                          end
                        end

                        function envoy_on_response(response_handle)
                        end

                  - name: envoy.filters.http.jwt_authn
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication
                      providers:
                        oidc:
                          issuer: "${OIDC_ISSUER}"
                          audiences: ["${OIDC_AUDIENCE}"]
                          forward_payload_header: x-jwt-payload
                          remote_jwks:
                            http_uri:
                              uri: "${OIDC_JWKS_URI}"
                              cluster: oidc_jwks
                              timeout: 5s
                      rules:
                        - match:
                            prefix: "/health"
                        - match:
                            safe_regex:
                              google_re2: {}
                              regex: '^/auth/login(?:\?.*)?$'
                        - match:
                            safe_regex:
                              google_re2: {}
                              regex: '^/auth/callback(?:\?.*)?$'
                        - match:
                            safe_regex:
                              google_re2: {}
                              regex: '^/auth/session(?:\?.*)?$'
                        - match:
                            safe_regex:
                              google_re2: {}
                              regex: '^/auth/logout(?:\?.*)?$'
                        - match:
                            prefix: "/"
                          requires:
                            provider_name: oidc

                  - name: envoy.filters.http.ext_authz
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
                      transport_api_version: V3
                      http_service:
                        server_uri:
                          uri: http://opa:8181
                          cluster: opa
                          timeout: 1s
                        path_prefix: "/v1/data/rbac/allow"
                        authorization_request:
                          allowed_headers:
                            patterns:
                              - exact: authorization
                              - exact: x-jwt-payload
                              - exact: :path
                              - exact: :method

                  - name: envoy.filters.http.grpc_web
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.grpc_web.v3.GrpcWeb

                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
      per_connection_buffer_limit_bytes: 1048576

  clusters:
    - name: main_api
      connect_timeout: 0.5s
      type: STRICT_DNS
      lb_policy: ROUND_ROBIN
      circuit_breakers:
        thresholds:
          - priority: DEFAULT
            max_connections: 1024
            max_requests: 8192
            max_retries: 3
      outlier_detection:
        consecutive_5xx: 5
        interval: 10s
        base_ejection_time: 30s
        max_ejection_percent: 50
      per_connection_buffer_limit_bytes: 1048576
      load_assignment:
        cluster_name: main_api
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: main-api
                      port_value: 50051
      typed_extension_protocol_options:
        envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
          "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
          explicit_http_config:
            http2_protocol_options:
              max_concurrent_streams: 1000
              initial_stream_window_size: 1048576
              initial_connection_window_size: 2097152

    - name: auth_api
      connect_timeout: 0.5s
      type: STRICT_DNS
      lb_policy: ROUND_ROBIN
      circuit_breakers:
        thresholds:
          - priority: DEFAULT
            max_connections: 512
            max_requests: 4096
            max_retries: 3
      outlier_detection:
        consecutive_5xx: 5
        interval: 10s
        base_ejection_time: 30s
        max_ejection_percent: 50
      load_assignment:
        cluster_name: auth_api
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: auth-api
                      port_value: 8081

    - name: opa
      connect_timeout: 0.25s
      type: STRICT_DNS
      lb_policy: ROUND_ROBIN
      circuit_breakers:
        thresholds:
          - priority: DEFAULT
            max_connections: 256
            max_requests: 2048
            max_retries: 1
      outlier_detection:
        consecutive_5xx: 5
        interval: 10s
        base_ejection_time: 30s
        max_ejection_percent: 50
      load_assignment:
        cluster_name: opa
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: opa
                      port_value: 8181

    - name: oidc_jwks
      connect_timeout: 2s
      type: LOGICAL_DNS
      dns_lookup_family: V4_ONLY
      lb_policy: ROUND_ROBIN
      outlier_detection:
        consecutive_5xx: 5
        interval: 10s
        base_ejection_time: 30s
        max_ejection_percent: 50
      load_assignment:
        cluster_name: oidc_jwks
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: ${OIDC_JWKS_HOST}
                      port_value: ${OIDC_JWKS_PORT}

admin:
  access_log_path: /tmp/admin_access.log
  address:
    socket_address:
      address: 0.0.0.0
      port_value: 9901
