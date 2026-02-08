package rbac_test

import data.rbac

test_admin_allowed {
  rbac.decision with input as {
    "user": {"id": "u1", "roles": ["admin"]},
    "action": "delete",
    "resource": {"owner_id": "u2"}
  }
}

test_owner_read_allowed {
  rbac.decision with input as {
    "user": {"id": "u1", "roles": ["user"]},
    "action": "read",
    "resource": {"owner_id": "u1"}
  }
}

test_non_owner_read_denied {
  not rbac.decision with input as {
    "user": {"id": "u1", "roles": ["user"]},
    "action": "read",
    "resource": {"owner_id": "u2"}
  }
}

test_metadata_service_ext_authz_allowed_with_base64_payload_sub {
  rbac.allow["api.v1.MetadataService"]["ListMetadata"] with input as {
    "attributes": {
      "request": {
        "http": {
          "path": "/api.v1.MetadataService/ListMetadata",
          "headers": {
            "x-jwt-payload": "eyJzdWIiOiJ0ZXN0LXVzZXIifQ"
          }
        }
      }
    }
  }
}

test_metadata_service_ext_authz_allowed_with_raw_json_payload_sub {
  rbac.allow["api.v1.MetadataService"]["ListMetadata"] with input as {
    "attributes": {
      "request": {
        "http": {
          "path": "/api.v1.MetadataService/ListMetadata",
          "headers": {
            "x-jwt-payload": "{\"sub\":\"test-user\"}"
          }
        }
      }
    }
  }
}

test_metadata_service_ext_authz_denied_without_sub {
  not rbac.allow["api.v1.MetadataService"]["ListMetadata"] with input as {
    "attributes": {
      "request": {
        "http": {
          "path": "/api.v1.MetadataService/ListMetadata",
          "headers": {
            "x-jwt-payload": "eyJyb2xlcyI6WyJhZG1pbiJdfQ"
          }
        }
      }
    }
  }
}

test_metadata_service_ext_authz_denied_for_malformed_base64_payload {
  not rbac.allow["api.v1.MetadataService"]["ListMetadata"] with input as {
    "attributes": {
      "request": {
        "http": {
          "path": "/api.v1.MetadataService/ListMetadata",
          "headers": {
            "x-jwt-payload": "%%%not-base64%%%"
          }
        }
      }
    }
  }
}

test_metadata_service_ext_authz_denied_for_malformed_json_payload {
  not rbac.allow["api.v1.MetadataService"]["ListMetadata"] with input as {
    "attributes": {
      "request": {
        "http": {
          "path": "/api.v1.MetadataService/ListMetadata",
          "headers": {
            "x-jwt-payload": "eyJzdWIiOiJ4Ig"
          }
        }
      }
    }
  }
}

test_metadata_service_ext_authz_denied_without_forwarded_jwt_payload {
  not rbac.allow["api.v1.MetadataService"]["ListMetadata"] with input as {
    "attributes": {
      "request": {
        "http": {
          "path": "/api.v1.MetadataService/ListMetadata",
          "headers": {}
        }
      }
    }
  }
}

# Defense-in-depth guard: /auth/login bypasses JWT and ext_authz at Envoy for OAuth bootstrap.
# If route bypass is removed or misconfigured, policy should still deny empty identities.
test_auth_login_would_be_denied_without_identity {
  not rbac.decision with input as {
    "user": {"id": "", "roles": []},
    "action": "read",
    "resource": {"owner_id": "owner-1"},
    "request": {"path": "/auth/login", "method": "GET"}
  }
}

# Defense-in-depth guard: /auth/callback is Envoy-bypassed during OAuth redirects.
# This test ensures OPA would deny unauthenticated access if the bypass no longer applied.
test_auth_callback_would_be_denied_without_identity {
  not rbac.decision with input as {
    "user": {"id": "", "roles": []},
    "action": "read",
    "resource": {"owner_id": "owner-2"},
    "request": {"path": "/auth/callback", "method": "GET"}
  }
}
