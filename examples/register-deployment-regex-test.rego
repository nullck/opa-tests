package kubernetes.admission

operations = {"CREATE", "UPDATE"}

deny[msg] {
  input.request.kind.kind == "Pod"
  image := input.request.object.spec.containers[_].image
  check_image(image)
  msg := sprintf("image must needs comes from a trusted register and cannot contains the tag latest: %v", [image])
}

deny[msg] {
  input.request.kind.kind == "StatefulSet"
  image := input.request.object.spec.template.spec.containers[_].image
  check_image(image)
  msg := sprintf("image must needs comes from a trusted register and cannot contains the tag latest: %v", [image])
}

deny[msg] {
  input.request.kind.kind == "ReplicaSet"
  image := input.request.object.spec.template.spec.containers[_].image
  check_image(image)
  msg := sprintf("image must needs comes from a trusted register and cannot contains the tag latest: %v", [image])
}

deny[msg] {
  input.request.kind.kind == "DaemonSet"
  image := input.request.object.spec.template.spec.containers[_].image
  check_image(image)
  msg := sprintf("image must needs comes from a trusted register and cannot contains the tag latest: %v", [image])
}

deny[msg] {
  input.request.kind.kind == "Deployment"
  image := input.request.object.spec.template.spec.containers[_].image
  check_image(image)
  msg := sprintf("image must needs comes from a trusted register and cannot contains the tag latest: %v", [image])
}

check_image(image) {
  not re_match(`^((827942265855|024148652745|387984977604|504749939156|681274060675|463541169828|827942265855)\.dkr\.ecr\.(us|eu|ap)\-(east|central|west|southeast)\-1\.amazonaws.com|nullck)`, image)
}

check_image(image) {
  [_, image_tag] := split(image, ":")
  image_tag == "latest"
}

check_image(image) {
  not contains(image, ":")
}

