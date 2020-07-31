#!/bin/bash

if [ -z $1 ]; then
  echo "use a parameter like install or destroy"
  exit 0
fi

CLUSTER_NAME="opa"
CREATE_REGO="kubectl create configmap"

if [ "$1" == "install" ]; then
  kind create  cluster --name ${CLUSTER_NAME} --config kind.yaml


elif [ "$1" == "opa" ]; then
  kubectl create ns opa
  kubectl create -n opa secret tls opa-server --cert=server.crt --key=server.key
  kubectl apply -f admission_control.yaml
  kubectl apply -f webhook-configuration.yaml
  kubectl label ns kube-system openpolicyagent.org/webhook=ignore
  kubectl label ns opa openpolicyagent.org/webhook=ignore

  ## rego rules
  $CREATE_REGO labels -n opa --from-file=../examples/labels.rego
  $CREATE_REGO protect-namespace -n opa --from-file=../examples/protect-namespace-alternative-version.rego
  $CREATE_REGO pod-security -n opa --from-file=../examples/root.rego
elif [ "$1" == "destroy" ]; then
  kind delete cluster --name ${CLUSTER_NAME}
fi

exit 0
