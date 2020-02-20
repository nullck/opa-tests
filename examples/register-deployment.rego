package kubernetes.admission

deny[msg] {
  input.request.kind.kind == "Deployment"
  image := input.request.object.spec.template.spec.containers[_].image
  not startswith(image)
  msg := sprintf("image must needs comes from a trusted register: %v", [image])
}
