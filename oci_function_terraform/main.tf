#############################################
# OCI CIS Scanner Function - Terraform
#############################################
# This Terraform configuration deploys:
# - Function Application
# - Function with HTTP trigger (API Gateway)
# - Required IAM policies for resource principal
# - Container registry for function image
#############################################

terraform {
  required_version = ">= 1.0.0"
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 5.0.0"
    }
  }
}

# Variables
variable "tenancy_ocid" {
  description = "The OCID of your tenancy"
  type        = string
}

variable "user_ocid" {
  description = "The OCID of the user deploying this"
  type        = string
}

variable "fingerprint" {
  description = "API key fingerprint"
  type        = string
}

variable "private_key_path" {
  description = "Path to the API private key"
  type        = string
}

variable "region" {
  description = "OCI region (e.g., us-ashburn-1)"
  type        = string
}

variable "compartment_ocid" {
  description = "The OCID of the compartment to deploy into"
  type        = string
}

variable "function_api_key" {
  description = "API key for authenticating to the function"
  type        = string
  default     = ""
  sensitive   = true
}

# Provider
provider "oci" {
  tenancy_ocid     = var.tenancy_ocid
  user_ocid        = var.user_ocid
  fingerprint      = var.fingerprint
  private_key_path = var.private_key_path
  region           = var.region
}

# Random API key if not provided
resource "random_password" "api_key" {
  count   = var.function_api_key == "" ? 1 : 0
  length  = 32
  special = false
}

locals {
  api_key = var.function_api_key != "" ? var.function_api_key : random_password.api_key[0].result
}

# Get tenancy namespace for container registry
data "oci_objectstorage_namespace" "ns" {
  compartment_id = var.tenancy_ocid
}

locals {
  namespace = data.oci_objectstorage_namespace.ns.namespace
}

# VCN for Function
resource "oci_core_vcn" "function_vcn" {
  compartment_id = var.compartment_ocid
  display_name   = "cis-scanner-vcn"
  cidr_blocks    = ["10.0.0.0/16"]
  dns_label      = "cisscanner"
}

resource "oci_core_internet_gateway" "igw" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.function_vcn.id
  display_name   = "cis-scanner-igw"
  enabled        = true
}

resource "oci_core_route_table" "rt" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.function_vcn.id
  display_name   = "cis-scanner-rt"

  route_rules {
    network_entity_id = oci_core_internet_gateway.igw.id
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
  }
}

resource "oci_core_subnet" "function_subnet" {
  compartment_id    = var.compartment_ocid
  vcn_id            = oci_core_vcn.function_vcn.id
  display_name      = "cis-scanner-subnet"
  cidr_block        = "10.0.1.0/24"
  route_table_id    = oci_core_route_table.rt.id
  security_list_ids = [oci_core_vcn.function_vcn.default_security_list_id]
  dns_label         = "fnsubnet"
}

# Container Registry
resource "oci_artifacts_container_repository" "function_repo" {
  compartment_id = var.compartment_ocid
  display_name   = "cis-benchmark-scanner"
  is_public      = false
}

# Function Application
resource "oci_functions_application" "cis_scanner_app" {
  compartment_id = var.compartment_ocid
  display_name   = "cis-benchmark-scanner"
  subnet_ids     = [oci_core_subnet.function_subnet.id]

  config = {
    "FUNCTION_API_KEY" = local.api_key
  }
}

# Dynamic Group for Functions
resource "oci_identity_dynamic_group" "functions_dg" {
  compartment_id = var.tenancy_ocid
  name           = "cis-scanner-functions"
  description    = "Dynamic group for CIS scanner function"
  matching_rule  = "ALL {resource.type = 'fnfunc', resource.compartment.id = '${var.compartment_ocid}'}"
}

# IAM Policy for Function to read OCI resources
resource "oci_identity_policy" "function_policy" {
  compartment_id = var.tenancy_ocid
  name           = "cis-scanner-function-policy"
  description    = "Policy allowing CIS scanner function to read OCI resources"
  statements = [
    "Allow dynamic-group ${oci_identity_dynamic_group.functions_dg.name} to read all-resources in tenancy",
    "Allow dynamic-group ${oci_identity_dynamic_group.functions_dg.name} to inspect compartments in tenancy",
    "Allow dynamic-group ${oci_identity_dynamic_group.functions_dg.name} to inspect users in tenancy",
    "Allow dynamic-group ${oci_identity_dynamic_group.functions_dg.name} to inspect groups in tenancy",
    "Allow dynamic-group ${oci_identity_dynamic_group.functions_dg.name} to inspect policies in tenancy",
    "Allow dynamic-group ${oci_identity_dynamic_group.functions_dg.name} to inspect authentication-policies in tenancy"
  ]
}

# API Gateway
resource "oci_apigateway_gateway" "cis_scanner_gateway" {
  compartment_id = var.compartment_ocid
  display_name   = "cis-scanner-gateway"
  endpoint_type  = "PUBLIC"
  subnet_id      = oci_core_subnet.function_subnet.id
}

resource "oci_apigateway_deployment" "cis_scanner_deployment" {
  compartment_id = var.compartment_ocid
  gateway_id     = oci_apigateway_gateway.cis_scanner_gateway.id
  display_name   = "cis-scanner-deployment"
  path_prefix    = "/v1"

  specification {
    request_policies {
      cors {
        allowed_origins = ["*"]
        allowed_methods = ["GET", "POST", "OPTIONS"]
        allowed_headers = ["*"]
      }
    }

    routes {
      path    = "/scan"
      methods = ["POST"]

      request_policies {
        header_transformations {
          set_headers {
            items {
              name   = "x-expected-api-key"
              values = [local.api_key]
            }
          }
        }
      }

      backend {
        type        = "HTTP_BACKEND"
        url         = "https://functions.${var.region}.oci.oraclecloud.com"
        is_ssl_verify_disabled = false
      }

      logging_policies {
        access_log {
          is_enabled = true
        }
        execution_log {
          is_enabled = true
          log_level  = "INFO"
        }
      }
    }
  }
}

# Outputs
output "api_gateway_endpoint" {
  value       = "${oci_apigateway_gateway.cis_scanner_gateway.hostname}/v1/scan"
  description = "API Gateway endpoint for the CIS scanner"
}

output "api_key" {
  value       = local.api_key
  description = "API key for authenticating to the function"
  sensitive   = true
}

output "function_app_ocid" {
  value       = oci_functions_application.cis_scanner_app.id
  description = "OCID of the function application"
}

output "namespace" {
  value       = local.namespace
  description = "OCI namespace for container registry"
}

output "container_registry" {
  value       = "${var.region}.ocir.io/${local.namespace}/cis-benchmark-scanner"
  description = "Container registry path for the function image"
}

output "next_steps" {
  value = <<-EOT
    
    ============================================
    NEXT STEPS - Deploy the Function
    ============================================
    
    1. Login to OCI Registry:
       docker login ${var.region}.ocir.io -u ${local.namespace}/YOUR_USERNAME
    
    2. Build and push the function:
       cd oci_function
       fn build
       docker tag cis-benchmark-scanner:0.0.1 ${var.region}.ocir.io/${local.namespace}/cis-benchmark-scanner:0.0.1
       docker push ${var.region}.ocir.io/${local.namespace}/cis-benchmark-scanner:0.0.1
    
    3. Create the function:
       fn create function cis-benchmark-scanner cis-benchmark-scanner ${var.region}.ocir.io/${local.namespace}/cis-benchmark-scanner:0.0.1
    
    4. Update API Gateway deployment with the function OCID
    
    5. Test the function:
       curl -X POST ${oci_apigateway_gateway.cis_scanner_gateway.hostname}/v1/scan \
         -H "x-api-key: <your-api-key>" \
         -H "Content-Type: application/json"
    
    EOT
}
