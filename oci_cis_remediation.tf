# ============================================================================
# OCI CIS Benchmark Remediation - Terraform Configuration
# ============================================================================
# This Terraform configuration implements CIS benchmark controls for OCI.
# Apply after running the scanner to remediate identified misconfigurations.
#
# Usage:
#   1. Update variables in terraform.tfvars
#   2. terraform init
#   3. terraform plan
#   4. terraform apply
# ============================================================================

terraform {
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 5.0.0"
    }
  }
}

# ============================================================================
# Variables
# ============================================================================

variable "tenancy_ocid" {
  description = "OCID of the tenancy"
  type        = string
}

variable "region" {
  description = "OCI region"
  type        = string
}

variable "compartment_ocid" {
  description = "OCID of the compartment for security resources"
  type        = string
}

variable "admin_email" {
  description = "Email address for security notifications"
  type        = string
  default     = "security@example.com"
}

# ============================================================================
# Provider
# ============================================================================

provider "oci" {
  tenancy_ocid = var.tenancy_ocid
  region       = var.region
}

# ============================================================================
# CIS 1.4-1.6: Password Policy (Authentication Policy)
# ============================================================================
# Sets password complexity requirements per CIS recommendations

resource "oci_identity_authentication_policy" "cis_password_policy" {
  compartment_id = var.tenancy_ocid
  
  password_policy {
    # CIS 1.4: Minimum password length >= 14
    minimum_password_length = 14
    
    # CIS 1.5: Password must contain uppercase, lowercase, numbers, special chars
    is_lowercase_characters_required = true
    is_uppercase_characters_required = true
    is_numeric_characters_required   = true
    is_special_characters_required   = true
    
    # CIS 1.6: Password cannot be the username
    is_username_containment_allowed = false
  }
}

# ============================================================================
# CIS 3.1: Audit Log Retention
# ============================================================================
# Ensures audit logs are retained for at least 365 days

resource "oci_logging_log_group" "audit_log_group" {
  compartment_id = var.compartment_ocid
  display_name   = "cis-audit-log-group"
  description    = "Log group for CIS compliance - audit retention"
}

resource "oci_logging_log" "audit_log" {
  display_name = "audit-log"
  log_group_id = oci_logging_log_group.audit_log_group.id
  log_type     = "SERVICE"
  
  configuration {
    source {
      category    = "all"
      resource    = var.tenancy_ocid
      service     = "audit"
      source_type = "OCISERVICE"
    }
  }
  
  is_enabled         = true
  retention_duration = 365
}

# ============================================================================
# CIS 3.2: Default Tags for Resource Tracking
# ============================================================================

resource "oci_identity_tag_namespace" "security_tags" {
  compartment_id = var.tenancy_ocid
  description    = "Tags for security and compliance tracking"
  name           = "SecurityCompliance"
}

resource "oci_identity_tag" "created_by" {
  tag_namespace_id = oci_identity_tag_namespace.security_tags.id
  description      = "User who created the resource"
  name             = "CreatedBy"
}

resource "oci_identity_tag" "environment" {
  tag_namespace_id = oci_identity_tag_namespace.security_tags.id
  description      = "Environment classification"
  name             = "Environment"
  
  validator {
    validator_type = "ENUM"
    values         = ["production", "staging", "development", "test"]
  }
}

resource "oci_identity_tag" "data_classification" {
  tag_namespace_id = oci_identity_tag_namespace.security_tags.id
  description      = "Data classification level"
  name             = "DataClassification"
  
  validator {
    validator_type = "ENUM"
    values         = ["public", "internal", "confidential", "restricted"]
  }
}

# ============================================================================
# CIS 3.3: Notification Topic for Security Alerts
# ============================================================================

resource "oci_ons_notification_topic" "security_topic" {
  compartment_id = var.compartment_ocid
  name           = "cis-security-notifications"
  description    = "Topic for CIS security notifications"
}

resource "oci_ons_subscription" "admin_email" {
  compartment_id = var.compartment_ocid
  endpoint       = var.admin_email
  protocol       = "EMAIL"
  topic_id       = oci_ons_notification_topic.security_topic.id
}

# ============================================================================
# CIS 3.4: Event Rules for IAM Changes
# ============================================================================

resource "oci_events_rule" "iam_changes" {
  compartment_id = var.tenancy_ocid
  display_name   = "cis-iam-change-notifications"
  description    = "Notify on IAM changes per CIS 3.4"
  is_enabled     = true
  
  condition = jsonencode({
    eventType = [
      "com.oraclecloud.identitycontrolplane.createuser",
      "com.oraclecloud.identitycontrolplane.deleteuser",
      "com.oraclecloud.identitycontrolplane.updateuser",
      "com.oraclecloud.identitycontrolplane.creategroup",
      "com.oraclecloud.identitycontrolplane.deletegroup",
      "com.oraclecloud.identitycontrolplane.updategroup",
      "com.oraclecloud.identitycontrolplane.addusertoadmingroup",
      "com.oraclecloud.identitycontrolplane.removeuserfromadmingroup",
      "com.oraclecloud.identitycontrolplane.createpolicy",
      "com.oraclecloud.identitycontrolplane.deletepolicy",
      "com.oraclecloud.identitycontrolplane.updatepolicy"
    ]
  })
  
  actions {
    actions {
      action_type = "ONS"
      is_enabled  = true
      topic_id    = oci_ons_notification_topic.security_topic.id
    }
  }
}

resource "oci_events_rule" "network_changes" {
  compartment_id = var.tenancy_ocid
  display_name   = "cis-network-change-notifications"
  description    = "Notify on network changes per CIS 3.10-3.11"
  is_enabled     = true
  
  condition = jsonencode({
    eventType = [
      "com.oraclecloud.virtualnetwork.createvcn",
      "com.oraclecloud.virtualnetwork.deletevcn",
      "com.oraclecloud.virtualnetwork.updatevcn",
      "com.oraclecloud.virtualnetwork.createsecuritylist",
      "com.oraclecloud.virtualnetwork.deletesecuritylist",
      "com.oraclecloud.virtualnetwork.updatesecuritylist",
      "com.oraclecloud.virtualnetwork.createnetworksecuritygroup",
      "com.oraclecloud.virtualnetwork.deletenetworksecuritygroup",
      "com.oraclecloud.virtualnetwork.updatenetworksecuritygroup",
      "com.oraclecloud.virtualnetwork.createinternetgateway",
      "com.oraclecloud.virtualnetwork.deleteinternetgateway",
      "com.oraclecloud.virtualnetwork.createroutetable",
      "com.oraclecloud.virtualnetwork.deleteroutetable",
      "com.oraclecloud.virtualnetwork.updateroutetable"
    ]
  })
  
  actions {
    actions {
      action_type = "ONS"
      is_enabled  = true
      topic_id    = oci_ons_notification_topic.security_topic.id
    }
  }
}

# ============================================================================
# CIS 3.5: Cloud Guard
# ============================================================================

resource "oci_cloud_guard_cloud_guard_configuration" "enable_cloud_guard" {
  compartment_id   = var.tenancy_ocid
  reporting_region = var.region
  status           = "ENABLED"
}

resource "oci_cloud_guard_target" "tenancy_target" {
  compartment_id       = var.tenancy_ocid
  display_name         = "cis-tenancy-target"
  target_resource_id   = var.tenancy_ocid
  target_resource_type = "COMPARTMENT"
  
  depends_on = [oci_cloud_guard_cloud_guard_configuration.enable_cloud_guard]
}

# ============================================================================
# CIS 4.2: KMS Vault for Customer-Managed Keys
# ============================================================================

resource "oci_kms_vault" "security_vault" {
  compartment_id = var.compartment_ocid
  display_name   = "cis-security-vault"
  vault_type     = "DEFAULT"
}

resource "oci_kms_key" "master_encryption_key" {
  compartment_id = var.compartment_ocid
  display_name   = "cis-master-key"
  
  key_shape {
    algorithm = "AES"
    length    = 32  # 256-bit key
  }
  
  management_endpoint = oci_kms_vault.security_vault.management_endpoint
  
  protection_mode = "SOFTWARE"  # Use HSM for production
}

# ============================================================================
# IAM Policies for Least Privilege
# ============================================================================

resource "oci_identity_policy" "network_admin_policy" {
  compartment_id = var.tenancy_ocid
  name           = "cis-network-admin-policy"
  description    = "Network administrator policy per CIS least privilege"
  
  statements = [
    "Allow group NetworkAdmins to manage virtual-network-family in tenancy",
    "Allow group NetworkAdmins to manage load-balancers in tenancy",
    "Allow group NetworkAdmins to manage dns in tenancy"
  ]
}

resource "oci_identity_policy" "storage_admin_policy" {
  compartment_id = var.tenancy_ocid
  name           = "cis-storage-admin-policy"
  description    = "Storage administrator policy per CIS least privilege"
  
  statements = [
    "Allow group StorageAdmins to manage object-family in tenancy",
    "Allow group StorageAdmins to manage volume-family in tenancy",
    "Allow group StorageAdmins to manage file-family in tenancy"
  ]
}

resource "oci_identity_policy" "security_admin_policy" {
  compartment_id = var.tenancy_ocid
  name           = "cis-security-admin-policy"
  description    = "Security administrator policy per CIS least privilege"
  
  statements = [
    "Allow group SecurityAdmins to manage cloud-guard-family in tenancy",
    "Allow group SecurityAdmins to manage vaults in tenancy",
    "Allow group SecurityAdmins to manage keys in tenancy",
    "Allow group SecurityAdmins to manage secret-family in tenancy",
    "Allow group SecurityAdmins to read audit-events in tenancy",
    "Allow group SecurityAdmins to manage cloudevents-rules in tenancy"
  ]
}

# ============================================================================
# Outputs
# ============================================================================

output "password_policy_id" {
  value       = oci_identity_authentication_policy.cis_password_policy.id
  description = "ID of the CIS-compliant password policy"
}

output "security_notification_topic" {
  value       = oci_ons_notification_topic.security_topic.id
  description = "ID of the security notification topic"
}

output "cloud_guard_status" {
  value       = oci_cloud_guard_cloud_guard_configuration.enable_cloud_guard.status
  description = "Cloud Guard status"
}

output "kms_vault_id" {
  value       = oci_kms_vault.security_vault.id
  description = "ID of the KMS vault for encryption keys"
}

output "master_key_id" {
  value       = oci_kms_key.master_encryption_key.id
  description = "ID of the master encryption key"
}
