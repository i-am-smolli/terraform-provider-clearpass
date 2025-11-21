terraform {
  required_providers {
    clearpass = {
      source = "registry.terraform.io/hashicorp/clearpass"
    }
  }
}

provider "clearpass" {
  host          = "clearpass.example.com"
  client_id     = "your-oauth-client-id"
  client_secret = "your-oauth-client-secret"
  insecure      = false  # Set to true for self-signed certificates
}
