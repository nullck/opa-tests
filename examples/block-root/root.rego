package kubernetes.validating.psp_root

has_field(obj, field) {
   obj[field]
}

has_key(x, k) {
	_ = x[k]
}

kind = input.request.kind.kind

is_deployment {
	kind = "Deployment"
}

is_daemonset {
	kind = "DaemonSet"
}

is_statefulset {
	kind = "StatefulSet"
}

is_pod {
	kind = "Pod"
}

pods[podSpec] {
	is_deployment
    podSpec = input.request.object.spec.template
}

pods[podSpec] {
	is_daemonset
    podSpec = input.request.object.spec.template
}

pods[podSpec] {
	is_statefulset
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
    msg := "SecurityContext must be configured"
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
    obj := podSpec.spec
    has_field(obj, "securityContext")
    not has_key(obj.securityContext, "allowPrivilegeEscalation")
    msg := "SecurityContext allowPrivilegeEscalation must be configured"
}

deny [msg] {
	pods[podSpec]
    podSpec.metadata.annotations.podSecure
    value := podSpec.spec.securityContext.allowPrivilegeEscalation
    not (value == false)
    msg := sprintf("The securityContext: allowPrivilegeEscalation, Must be set with true value; found `%v`", [value])
}

