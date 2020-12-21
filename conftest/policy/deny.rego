package main

import data.kubernetes

name = input.metadata.name

deny[msg] {
  kubernetes.is_deployment
  not input.spec.template.spec.securityContext.runAsNonRoot

  msg = sprintf("Containers must not run as root in Deployment %s", [name])
}

required_deployment_selectors {
  input.spec.selector.matchLabels.app
  input.spec.selector.matchLabels.release
}

deny[msg] {
  kubernetes.is_deployment
  not required_deployment_selectors

  msg = sprintf("Deployment %s must provide app/release labels for pod selectors", [name])
}

required_ingress_annotation {
  input.metadata.annotations["cert-manager.io/cluster-issuer"] == "letsencrypt-http-issuer"
}

deny[msg] {
  kubernetes.is_ingress
  not required_ingress_annotation
  msg = sprintf("Ingress %s should have a cert-manager annotation with a value of 'letsencrypt-http-issuer'", [name])
}
