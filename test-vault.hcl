storage "file" {
  path = "./storage"
}

listener "tcp" {
  address = "127.0.0.1:8200"
  tls_disable = "true"
  unauthenticated_metrics_access = true
}

ui = true
