# Outputs for OCI Load Balancer

output "load_balancer_ip" {
  value = oci_load_balancer.my_load_balancer.ip_address // Replace with actual load balancer IP retrieval
}

output "load_balancer_dns_name" {
  value = oci_load_balancer.my_load_balancer.dns_name // Replace with actual DNS name retrieval
}

output "load_balancer_connection_details" {
  value = oci_load_balancer.my_load_balancer.connection_details // Replace with actual connection details retrieval
}