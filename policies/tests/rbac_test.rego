package rbac_test

import data.rbac

test_admin_allowed {
  rbac.allow with input as {
    "user": {"id": "u1", "roles": ["admin"]},
    "action": "delete",
    "resource": {"owner_id": "u2"}
  }
}

test_owner_read_allowed {
  rbac.allow with input as {
    "user": {"id": "u1", "roles": ["user"]},
    "action": "read",
    "resource": {"owner_id": "u1"}
  }
}

test_non_owner_read_denied {
  not rbac.allow with input as {
    "user": {"id": "u1", "roles": ["user"]},
    "action": "read",
    "resource": {"owner_id": "u2"}
  }
}
