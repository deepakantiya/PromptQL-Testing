# OCI Load Balancer Security Configuration

## Security Group
resource "oci_core_security_list" "load_balancer_security_list" {
  compartment_id = var.compartment_id
  display_name   = "load_balancer_security_list"
  ingress_security_rules {
    description = "Allow HTTPS traffic from the Internet"
    protocol   = "6" # TCP
    src_addr  = "0.0.0.0/0" # From any source
    tcp_options {
      "min" = 443
      "max" = 443
    }
  }
  egress_security_rules {
    description = "Allow all outbound traffic"
    protocol   = "all" # All protocols
    destination = "0.0.0.0/0" # To any destination
  }
  # Additional NSG Rules can be added here
}

## Network Security Group (NSG) Rules
resource "oci_core_network_security_group" "load_balancer_nsg" {
  compartment_id = var.compartment_id
  display_name   = "load_balancer_nsg"
  security_rules {
    description = "Allow HTTPS traffic from the Internet"
    protocol   = "6" # TCP
    source     = "0.0.0.0/0" # From any source
    tcp_options {
      "min" = 443
      "max" = 443
    }
  }
  # Additional NSG Rules can be added here
}
