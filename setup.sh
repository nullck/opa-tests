#!/bin/bash

CREATE_REGO="kubectl create configmap" 

kubectl create ns opa
kubectl create -n opa secret tls opa-server --cert=server.crt --key=server.key
kubectl apply -f admission_control.yaml
kubectl apply -f webhook-configuration.yaml
kubectl label ns kube-system openpolicyagent.org/webhook=ignore
kubectl label ns opa openpolicyagent.org/webhook=ignore

## rego rules
$CREATE_REGO labels -n opa --from-file=examples/labels.rego
$CREATE_REGO protect-namespace -n opa --from-file=examples/protect-namespace.rego
$CREATE_REGO register -n opa --from-file=examples/register-deployment-regex-test.rego

