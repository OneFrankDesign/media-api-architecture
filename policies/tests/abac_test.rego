package abac_test

import data.abac

base_input := {
  "attributes": {
    "request": {
      "http": {
        "path": "/api.v1.MetadataService/GetMetadata",
        "headers": {
          "x-jwt-payload": "{\"sub\":\"owner-1\",\"roles\":[\"user\"],\"org\":\"org-a\"}"
        }
      }
    }
  },
  "resource": {
    "owner_id": "owner-1",
    "status": "METADATA_STATUS_READY",
    "visibility": "VISIBILITY_PRIVATE",
    "custom_metadata": {
      "org": "org-a",
      "project": "project-a"
    }
  }
}

test_health_allowed {
  abac.allow["api.v1.MetadataService"]["Health"]
}

test_authenticated_user_can_create_metadata {
  abac.allow["api.v1.MetadataService"]["CreateMetadata"] with input as base_input
}

test_owner_can_get_metadata {
  abac.allow["api.v1.MetadataService"]["GetMetadata"] with input as base_input
}

test_admin_can_get_foreign_metadata {
  abac.allow["api.v1.MetadataService"]["GetMetadata"] with input as {
    "attributes": {
      "request": {
        "http": {
          "path": "/api.v1.MetadataService/GetMetadata",
          "headers": {
            "x-jwt-payload": "{\"sub\":\"admin-1\",\"roles\":[\"admin\"]}"
          }
        }
      }
    },
    "resource": {
      "owner_id": "owner-2"
    }
  }
}

test_non_owner_non_admin_denied {
  not abac.allow["api.v1.MetadataService"]["GetMetadata"] with input as {
    "attributes": {
      "request": {
        "http": {
          "path": "/api.v1.MetadataService/GetMetadata",
          "headers": {
            "x-jwt-payload": "{\"sub\":\"user-2\",\"roles\":[\"user\"]}"
          }
        }
      }
    },
    "resource": {
      "owner_id": "owner-1"
    }
  }
}

test_missing_sub_denied {
  not abac.allow["api.v1.MetadataService"]["ListMetadata"] with input as {
    "attributes": {
      "request": {
        "http": {
          "path": "/api.v1.MetadataService/ListMetadata",
          "headers": {
            "x-jwt-payload": "{\"roles\":[\"user\"]}"
          }
        }
      }
    }
  }
}

test_malformed_forwarded_claims_denied {
  not abac.allow["api.v1.MetadataService"]["ListMetadata"] with input as {
    "attributes": {
      "request": {
        "http": {
          "path": "/api.v1.MetadataService/ListMetadata",
          "headers": {
            "x-jwt-payload": "%%%not-json%%%"
          }
        }
      }
    }
  }
}
