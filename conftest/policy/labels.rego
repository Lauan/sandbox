package main

import data.kubernetes

name = input.metadata.name

required_deployment_labels {
    input.metadata.labels["environment"]
}

deny[msg] {
  kubernetes.is_deployment
  not required_deployment_labels
  msg = sprintf("%s must include environment label", [name])
}
