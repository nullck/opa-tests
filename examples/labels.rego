package kubernetes.admission

operations = {"CREATE", "UPDATE"}

deny[msg] {
  input.request.kind.kind == "Pod"
  labels := input.request.object.metadata.labels
  check_labels(labels)
  msg = "please set the labels costCenter, app and environment"
}

deny[msg] {
  input.request.kind.kind == "Deployment"
  labels := input.request.object.metadata.labels
  check_labels(labels)
  msg = "please set the labels costCenter, app and environment"
}

deny[msg] {
  input.request.kind.kind == "ReplicaSet"
  labels := input.request.object.metadata.labels
  check_labels(labels)
  msg = "please set the labels costCenter, app and environment"
}

deny[msg] {
  input.request.kind.kind == "DaemonSet"
  labels := input.request.object.metadata.labels
  check_labels(labels)
  msg = "please set the labels costCenter, app and environment"
}

check_labels(labels) {
  not labels.costCenter
}

check_labels(labels) {
  not labels.environment
}

check_labels(labels) {
  not labels.app
}
