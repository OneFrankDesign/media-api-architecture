package rbac

import future.keywords.if
import future.keywords.in

default decision := false

decision if {
  "admin" in object.get(object.get(input, "user", {}), "roles", [])
}

decision if {
  input.action == "read"
  resource := object.get(input, "resource", {})
  user := object.get(input, "user", {})
  user_id := object.get(user, "id", "")
  user_id != ""
  object.get(resource, "owner_id", "") == user_id
}

decision if {
  input.action == "health"
}

# Envoy ext_authz CheckRequest path for metadata service calls.
# JWT validation runs before ext_authz at the gateway; if validation succeeds,
# Envoy forwards x-jwt-payload to OPA for defense-in-depth checks.
decision if {
  claims := decoded_forwarded_claims()
  sub := object.get(claims, "sub", "")
  is_string(sub)
  sub != ""
}

decoded_forwarded_claims() := claims if {
  payload := forwarded_jwt_payload()
  claims := json.unmarshal(payload)
}

decoded_forwarded_claims() := claims if {
  payload := forwarded_jwt_payload()
  decoded := base64url.decode(payload)
  claims := json.unmarshal(decoded)
}

forwarded_jwt_payload() := payload if {
  attributes := object.get(input, "attributes", {})
  request := object.get(attributes, "request", {})
  http := object.get(request, "http", {})
  headers := object.get(http, "headers", {})
  payload := object.get(headers, "x-jwt-payload", "")
  payload != ""
}

# Envoy appends the original request path to the configured OPA decision path.
# These route-specific document keys return a boolean decision for each method.
allow["api.v1.MetadataService"]["Health"] := true

allow["api.v1.MetadataService"]["CreateMetadata"] := decision
allow["api.v1.MetadataService"]["GetMetadata"] := decision
allow["api.v1.MetadataService"]["ListMetadata"] := decision
allow["api.v1.MetadataService"]["UpdateMetadata"] := decision
allow["api.v1.MetadataService"]["DeleteMetadata"] := decision
