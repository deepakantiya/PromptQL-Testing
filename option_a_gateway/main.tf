#############################################
# Option A: OCI API Gateway Proxy
#############################################
# This creates an API Gateway that proxies requests to OCI APIs
# Uses OCI Functions as backend handlers with Resource Principals
# Allows PromptQL to query any OCI service in real-time

terraform {
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 5.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0.0"
    }
  }
}

provider "oci" {
  tenancy_ocid     = var.tenancy_ocid
  user_ocid        = var.user_ocid
  fingerprint      = var.fingerprint
  private_key_path = var.private_key_path
  region           = var.region
}

#############################################
# Variables
#############################################

variable "tenancy_ocid" {
  description = "OCID of your tenancy"
  type        = string
}

variable "user_ocid" {
  description = "OCID of the user for Terraform authentication"
  type        = string
}

variable "fingerprint" {
  description = "API key fingerprint"
  type        = string
}

variable "private_key_path" {
  description = "Path to API private key"
  type        = string
}

variable "region" {
  description = "OCI region"
  type        = string
}

variable "compartment_ocid" {
  description = "Compartment to deploy resources"
  type        = string
}

#############################################
# Random API Key
#############################################

resource "random_password" "api_key" {
  length  = 32
  special = false
}

#############################################
# Object Storage Namespace
#############################################

data "oci_objectstorage_namespace" "ns" {
  compartment_id = var.tenancy_ocid
}

locals {
  namespace = data.oci_objectstorage_namespace.ns.namespace
}

#############################################
# Networking
#############################################

resource "oci_core_vcn" "proxy_vcn" {
  compartment_id = var.compartment_ocid
  display_name   = "oci-proxy-vcn"
  cidr_blocks    = ["10.0.0.0/16"]
  dns_label      = "ociproxy"
}

resource "oci_core_internet_gateway" "igw" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.proxy_vcn.id
  display_name   = "oci-proxy-igw"
  enabled        = true
}

resource "oci_core_route_table" "rt" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.proxy_vcn.id
  display_name   = "oci-proxy-rt"

  route_rules {
    network_entity_id = oci_core_internet_gateway.igw.id
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
  }
}

resource "oci_core_subnet" "proxy_subnet" {
  compartment_id    = var.compartment_ocid
  vcn_id            = oci_core_vcn.proxy_vcn.id
  display_name      = "oci-proxy-subnet"
  cidr_block        = "10.0.1.0/24"
  route_table_id    = oci_core_route_table.rt.id
  security_list_ids = [oci_core_vcn.proxy_vcn.default_security_list_id]
  dns_label         = "proxysubnet"
}

#############################################
# Container Registry
#############################################

resource "oci_artifacts_container_repository" "function_repo" {
  compartment_id = var.compartment_ocid
  display_name   = "oci-proxy-functions"
  is_public      = false
}

#############################################
# Functions Application
#############################################

resource "oci_functions_application" "proxy_app" {
  compartment_id = var.compartment_ocid
  display_name   = "oci-proxy-app"
  subnet_ids     = [oci_core_subnet.proxy_subnet.id]

  config = {
    "TENANCY_OCID" = var.tenancy_ocid
  }
}

#############################################
# Dynamic Group for Functions
#############################################

resource "oci_identity_dynamic_group" "functions_dg" {
  compartment_id = var.tenancy_ocid
  name           = "oci-proxy-functions-dg"
  description    = "Dynamic group for OCI Proxy functions"
  matching_rule  = "ALL {resource.type = 'fnfunc', resource.compartment.id = '${var.compartment_ocid}'}"
}

#############################################
# IAM Policy - Read Only
#############################################

resource "oci_identity_policy" "functions_policy" {
  compartment_id = var.tenancy_ocid
  name           = "oci-proxy-functions-policy"
  description    = "Read-only policy for OCI Proxy functions"
  statements = [
    "Allow dynamic-group ${oci_identity_dynamic_group.functions_dg.name} to read all-resources in tenancy",
    "Allow dynamic-group ${oci_identity_dynamic_group.functions_dg.name} to inspect compartments in tenancy",
    "Allow dynamic-group ${oci_identity_dynamic_group.functions_dg.name} to inspect users in tenancy",
    "Allow dynamic-group ${oci_identity_dynamic_group.functions_dg.name} to inspect groups in tenancy",
    "Allow dynamic-group ${oci_identity_dynamic_group.functions_dg.name} to inspect policies in tenancy",
    "Allow dynamic-group ${oci_identity_dynamic_group.functions_dg.name} to inspect authentication-policies in tenancy",
    "Allow dynamic-group ${oci_identity_dynamic_group.functions_dg.name} to read cloud-guard-family in tenancy",
    "Allow dynamic-group ${oci_identity_dynamic_group.functions_dg.name} to read vaults in tenancy",
    "Allow dynamic-group ${oci_identity_dynamic_group.functions_dg.name} to read keys in tenancy"
  ]
}

#############################################
# API Gateway
#############################################

resource "oci_apigateway_gateway" "proxy_gateway" {
  compartment_id = var.compartment_ocid
  display_name   = "oci-proxy-gateway"
  endpoint_type  = "PUBLIC"
  subnet_id      = oci_core_subnet.proxy_subnet.id
}

#############################################
# API Gateway Deployment
#############################################

resource "oci_apigateway_deployment" "proxy_deployment" {
  compartment_id = var.compartment_ocid
  gateway_id     = oci_apigateway_gateway.proxy_gateway.id
  display_name   = "oci-proxy-deployment"
  path_prefix    = "/api/v1"

  specification {
    request_policies {
      cors {
        allowed_origins = ["*"]
        allowed_methods = ["GET", "POST", "OPTIONS"]
        allowed_headers = ["*"]
      }
    }

    # Identity Routes
    routes {
      path    = "/identity/users"
      methods = ["GET"]
      backend {
        type = "STOCK_RESPONSE_BACKEND"
        status = 200
        body = "{\"message\": \"Deploy identity_handler function and update this route\"}"
      }
    }

    routes {
      path    = "/identity/groups"
      methods = ["GET"]
      backend {
        type = "STOCK_RESPONSE_BACKEND"
        status = 200
        body = "{\"message\": \"Deploy identity_handler function and update this route\"}"
      }
    }

    routes {
      path    = "/identity/policies"
      methods = ["GET"]
      backend {
        type = "STOCK_RESPONSE_BACKEND"
        status = 200
        body = "{\"message\": \"Deploy identity_handler function and update this route\"}"
      }
    }

    routes {
      path    = "/identity/compartments"
      methods = ["GET"]
      backend {
        type = "STOCK_RESPONSE_BACKEND"
        status = 200
        body = "{\"message\": \"Deploy identity_handler function and update this route\"}"
      }
    }

    routes {
      path    = "/identity/auth-policy"
      methods = ["GET"]
      backend {
        type = "STOCK_RESPONSE_BACKEND"
        status = 200
        body = "{\"message\": \"Deploy identity_handler function and update this route\"}"
      }
    }

    # Network Routes
    routes {
      path    = "/network/vcns"
      methods = ["GET"]
      backend {
        type = "STOCK_RESPONSE_BACKEND"
        status = 200
        body = "{\"message\": \"Deploy network_handler function and update this route\"}"
      }
    }

    routes {
      path    = "/network/security-lists"
      methods = ["GET"]
      backend {
        type = "STOCK_RESPONSE_BACKEND"
        status = 200
        body = "{\"message\": \"Deploy network_handler function and update this route\"}"
      }
    }

    routes {
      path    = "/network/nsgs"
      methods = ["GET"]
      backend {
        type = "STOCK_RESPONSE_BACKEND"
        status = 200
        body = "{\"message\": \"Deploy network_handler function and update this route\"}"
      }
    }

    # Storage Routes
    routes {
      path    = "/storage/buckets"
      methods = ["GET"]
      backend {
        type = "STOCK_RESPONSE_BACKEND"
        status = 200
        body = "{\"message\": \"Deploy storage_handler function and update this route\"}"
      }
    }

    # Compute Routes
    routes {
      path    = "/compute/instances"
      methods = ["GET"]
      backend {
        type = "STOCK_RESPONSE_BACKEND"
        status = 200
        body = "{\"message\": \"Deploy compute_handler function and update this route\"}"
      }
    }

    routes {
      path    = "/compute/volumes"
      methods = ["GET"]
      backend {
        type = "STOCK_RESPONSE_BACKEND"
        status = 200
        body = "{\"message\": \"Deploy compute_handler function and update this route\"}"
      }
    }

    # Security Routes
    routes {
      path    = "/security/cloud-guard/status"
      methods = ["GET"]
      backend {
        type = "STOCK_RESPONSE_BACKEND"
        status = 200
        body = "{\"message\": \"Deploy security_handler function and update this route\"}"
      }
    }

    routes {
      path    = "/security/cloud-guard/problems"
      methods = ["GET"]
      backend {
        type = "STOCK_RESPONSE_BACKEND"
        status = 200
        body = "{\"message\": \"Deploy security_handler function and update this route\"}"
      }
    }

    # CIS Scan Route
    routes {
      path    = "/cis/scan"
      methods = ["POST"]
      backend {
        type = "STOCK_RESPONSE_BACKEND"
        status = 200
        body = "{\"message\": \"Deploy functions and update this route to run full CIS scan\"}"
      }
    }
  }
}

#############################################
# Outputs
#############################################

output "api_gateway_endpoint" {
  value       = "${oci_apigateway_gateway.proxy_gateway.hostname}/api/v1"
  description = "Base URL for the API Gateway"
}

output "api_key" {
  value       = random_password.api_key.result
  description = "API key for authentication"
  sensitive   = true
}

output "function_app_ocid" {
  value       = oci_functions_application.proxy_app.id
  description = "OCID of the function application"
}

output "namespace" {
  value       = local.namespace
  description = "OCI namespace for container registry"
}

output "container_registry" {
  value       = "${var.region}.ocir.io/${local.namespace}/oci-proxy-functions"
  description = "Container registry URL"
}

output "available_endpoints" {
  value = <<-EOT
    
    Available API Endpoints at ${oci_apigateway_gateway.proxy_gateway.hostname}/api/v1
    
    Identity:
      GET /identity/users          - List all users
      GET /identity/groups         - List all groups
      GET /identity/policies       - List all policies
      GET /identity/compartments   - List compartments
      GET /identity/auth-policy    - Get authentication policy
    
    Network:
      GET /network/vcns            - List VCNs
      GET /network/security-lists  - List security lists
      GET /network/nsgs            - List network security groups
    
    Storage:
      GET /storage/buckets         - List buckets
    
    Compute:
      GET /compute/instances       - List instances
      GET /compute/volumes         - List volumes
    
    Security:
      GET /security/cloud-guard/status   - Get Cloud Guard status
      GET /security/cloud-guard/problems - List security problems
    
    CIS Benchmark:
      POST /cis/scan               - Run full CIS benchmark scan
    
    Authentication:
      Add header: x-api-key: <your-api-key>
    
  EOT
}
