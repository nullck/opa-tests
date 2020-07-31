package kubernetes.admission

operations = {"CREATE", "UPDATE"}

deny[msg] {
  input.request.kind.kind == "Deployment"
  image := input.request.object.spec.template.spec.containers[_].image
  not re_match(`^(827942265855|024148652745|387984977604|504749939156|681274060675|463541169828|827942265855)\.dkr\.ecr\.(us|eu|ap)\-(east|central|west|southeast)\-1\.amazonaws.com`, image)
  msg := sprintf("image must needs comes from a trusted register: %v", [image])
}
