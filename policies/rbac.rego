package rbac

import future.keywords.if
import future.keywords.in

default allow := false

allow if {
  "admin" in input.user.roles
}

allow if {
  input.action == "read"
  input.resource.owner_id == input.user.id
}

allow if {
  input.action == "health"
}
