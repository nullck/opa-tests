package kubernetes.admission

deny[msg] {
  input.request.kind.kind == "Pod"
  image := input.request.object.spec.containers[_].image
  not startswith(image, "681274060675.dkr.ecr.eu-central-1.amazonaws.com")
  msg := sprintf("image must needs comes from a trusted register: %v", [image])
}
