package kubernetes.admission

has_field(obj, field) {
   obj[field]
}

has_key(x, k) {
  _ = x[k]
}

kind = input.request.kind.kind

is_not_pod {
  re_match(`(Deployment|DaemonSet|StatefulSet)`, kind)
}

is_pod {
  kind = "Pod"
}

pods[podSpec] {
    is_not_pod
    podSpec = input.request.object.spec.template
}

pods[podSpec] {
    is_pod
    podSpec = input.request.object
}

deny [msg] {
    pods[podSpec]
    podSpec.metadata.annotations.podSecure
    not podSpec.spec.securityContext
    msg := "SecurityContext must be configured in Pod Level"
}

deny [msg] {
    pods[podSpec]
    podSpec.metadata.annotations.podSecure
    obj := podSpec.spec.containers[_]
    not has_key(obj, "securityContext")
    msg := "SecurityContext must be configured in Container Level"
}

deny [msg] {
    pods[podSpec]
    podSpec.metadata.annotations.podSecure
    obj := podSpec.spec
    has_field(obj, "securityContext")
    not has_key(obj.securityContext, "runAsNonRoot")
    msg := "SecurityContext runAsNonRoot must be configured"
}

deny [msg] {
    pods[podSpec]
    podSpec.metadata.annotations.podSecure
    value := podSpec.spec.securityContext.runAsNonRoot
    not (value == true)
    msg := sprintf("The securityContext: runAsNonRoot, Must be set with true value; found `%v`", [value])
}

deny [msg] {
    pods[podSpec]
    podSpec.metadata.annotations.podSecure
    obj := podSpec.spec.containers[_]
    has_field(obj, "securityContext")
    not has_key(obj.securityContext, "allowPrivilegeEscalation")
    msg := "SecurityContext allowPrivilegeEscalation must be configured"
}

deny [msg] {
    pods[podSpec]
    podSpec.metadata.annotations.podSecure
    value := podSpec.spec.containers[_].securityContext.allowPrivilegeEscalation
    not (value == false)
    msg := sprintf("The securityContext: allowPrivilegeEscalation, Must be set with false value; found `%v`", [value])
}
