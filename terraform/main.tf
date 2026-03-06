# OCI Load Balancer Configuration

resource "oci_load_balancer" "example_load_balancer" {
  compartment_id = var.compartment_id
  display_name   = "example_load_balancer"
  shape         = "100Mbps"
  is_private    = false
  subnet_ids    = [var.subnet_id]
  # Additional configuration options
}

resource "oci_load_balancer_backend_set" "example_backend_set" {
  load_balancer_id = oci_load_balancer.example_load_balancer.id
  name            = "example_backend_set"
  policy          = "ROUND_ROBIN"
  health_checker {
    protocol        = "HTTP"
    port            = 80
    url_path        = "/"
    retries         = 3
    timeout         = 5
    interval        = 30
  }
}

resource "oci_load_balancer_listener" "example_listener" {
  load_balancer_id = oci_load_balancer.example_load_balancer.id
  name            = "example_listener"
  default_backend_set = oci_load_balancer_backend_set.example_backend_set.name
  port            = 443
  protocol        = "HTTPS"
  ssl_configuration {
    ssl_policy_name = "CustomSSLPolicy"
    certificate_name = oci_load_balancer_certificate.example_certificate.name
  }
}

resource "oci_load_balancer_certificate" "example_certificate" {
  load_balancer_id = oci_load_balancer.example_load_balancer.id
  name            = "example_certificate"
  certificate     = file("${path.module}/cert.pem")
  private_key     = file("${path.module}/private_key.pem")
}  

# CIS Benchmarks Compliance
# Configure security rules, tags, and best practices as per your organization’s security policy for compliance with CIS benchmarks.