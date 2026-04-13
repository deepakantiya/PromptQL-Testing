import executor
"""
OCI CIS Benchmark Scanner - Serverless Function
================================================
This function scans an OCI tenancy for CIS benchmark compliance
and returns a detailed report.

Triggered via HTTP and uses Resource Principals for authentication.
"""

import io
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from fdk import response

import oci

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# API Key for authentication (set via function configuration)
EXPECTED_API_KEY = os.environ.get("FUNCTION_API_KEY", "")

# CIS Benchmark checks configuration
CIS_CHECKS = {
    "1.1": "Ensure service level admins are created to manage resources",
    "1.2": "Ensure permissions on all resources are given only to tenancy admin group",
    "1.3": "Ensure IAM administrators cannot update tenancy Administrators group",
    "1.4": "Ensure IAM password policy requires minimum length of 14",
    "1.5": "Ensure IAM password policy expires passwords within 365 days",
    "1.6": "Ensure IAM password policy prevents password reuse",
    "1.7": "Ensure MFA is enabled for all users with a console password",
    "1.8": "Ensure user API keys rotate within 90 days",
    "1.9": "Ensure user customer secret keys rotate within 90 days",
    "1.10": "Ensure user auth tokens rotate within 90 days",
    "1.11": "Ensure API keys are not created for tenancy administrator users",
    "1.12": "Ensure all OCI IAM user accounts have a valid email address",
    "2.1": "Ensure no security lists allow ingress from 0.0.0.0/0 to port 22",
    "2.2": "Ensure no security lists allow ingress from 0.0.0.0/0 to port 3389",
    "2.3": "Ensure no network security groups allow ingress from 0.0.0.0/0 to port 22",
    "2.4": "Ensure no network security groups allow ingress from 0.0.0.0/0 to port 3389",
    "2.5": "Ensure the default security list restricts all traffic",
    "2.6": "Ensure Oracle Integration Cloud (OIC) access is restricted to allowed sources",
    "2.7": "Ensure Oracle Analytics Cloud (OAC) access is restricted to allowed sources",
    "2.8": "Ensure Oracle Autonomous Database (ADB) access is restricted to allowed sources",
    "3.1": "Ensure audit log retention period is set to 365 days",
    "3.2": "Ensure default tags are used on resources",
    "3.3": "Create at least one notification topic and subscription for IAM changes",
    "3.4": "Create at least one notification topic and subscription for identity provider changes",
    "3.5": "Create at least one notification topic and subscription for IdP group mapping changes",
    "3.6": "Create at least one notification topic and subscription for IAM group changes",
    "3.7": "Create at least one notification topic and subscription for IAM policy changes",
    "3.8": "Create at least one notification topic and subscription for user changes",
    "3.9": "Create at least one notification topic and subscription for VCN changes",
    "3.10": "Create at least one notification topic and subscription for route table changes",
    "3.11": "Create at least one notification topic and subscription for security list changes",
    "3.12": "Create at least one notification topic and subscription for network security group changes",
    "3.13": "Create at least one notification topic and subscription for network gateways changes",
    "3.14": "Ensure VCN flow logging is enabled for all subnets",
    "3.15": "Ensure Cloud Guard is enabled in the root compartment",
    "3.16": "Ensure customer created budget exists",
    "4.1.1": "Ensure no Object Storage buckets are publicly visible",
    "4.1.2": "Ensure Object Storage Buckets are encrypted with Customer Managed Keys",
    "4.1.3": "Ensure Versioning is Enabled for Object Storage Buckets",
    "4.2.1": "Ensure Block Volumes are encrypted with Customer Managed Keys",
    "4.2.2": "Ensure boot volumes are encrypted with Customer Managed Keys",
    "5.1": "Create at least one compartment in your tenancy to store cloud resources",
    "5.2": "Ensure no resources are created in the root compartment"
}


def get_resource_principal_signer():
    """Get signer using Resource Principal authentication."""
    try:
        return oci.auth.signers.get_resource_principals_signer()
    except Exception as e:
        logger.error(f"Failed to get resource principal signer: {e}")
        raise


def get_all_compartments(identity_client, tenancy_id):
    """Get all active compartments in the tenancy."""
    compartments = [{"id": tenancy_id, "name": "root", "is_root": True}]
    
    try:
        response = oci.pagination.list_call_get_all_results(
            identity_client.list_compartments,
            tenancy_id,
            compartment_id_in_subtree=True,
            lifecycle_state="ACTIVE"
        )
        for comp in response.data:
            compartments.append({
                "id": comp.id,
                "name": comp.name,
                "is_root": False
            })
    except Exception as e:
        logger.warning(f"Error listing compartments: {e}")
    
    return compartments


def check_iam_password_policy(identity_client, tenancy_id):
    """Check IAM password policy settings (CIS 1.4, 1.5, 1.6)."""
    findings = []
    
    try:
        policy = identity_client.get_authentication_policy(tenancy_id).data
        pwd_policy = policy.password_policy
        
        # CIS 1.4 - Minimum length 14
        if pwd_policy.minimum_password_length < 14:
            findings.append({
                "check_id": "1.4",
                "status": "FAIL",
                "resource": "Tenancy Password Policy",
                "detail": f"Minimum password length is {pwd_policy.minimum_password_length}, should be at least 14"
            })
        else:
            findings.append({
                "check_id": "1.4",
                "status": "PASS",
                "resource": "Tenancy Password Policy",
                "detail": f"Minimum password length is {pwd_policy.minimum_password_length}"
            })
        
        # Check complexity requirements
        complexity_checks = [
            ("is_lowercase_characters_required", "lowercase"),
            ("is_uppercase_characters_required", "uppercase"),
            ("is_numeric_characters_required", "numeric"),
            ("is_special_characters_required", "special")
        ]
        
        missing_complexity = []
        for attr, name in complexity_checks:
            if not getattr(pwd_policy, attr, False):
                missing_complexity.append(name)
        
        if missing_complexity:
            findings.append({
                "check_id": "1.4b",
                "status": "FAIL",
                "resource": "Tenancy Password Policy",
                "detail": f"Missing complexity requirements: {', '.join(missing_complexity)}"
            })
        
    except Exception as e:
        findings.append({
            "check_id": "1.4",
            "status": "ERROR",
            "resource": "Tenancy Password Policy",
            "detail": f"Could not check password policy: {str(e)}"
        })
    
    return findings


def check_mfa_status(identity_client, tenancy_id):
    """Check MFA is enabled for all users with console password (CIS 1.7)."""
    findings = []
    users_without_mfa = []
    
    try:
        users = oci.pagination.list_call_get_all_results(
            identity_client.list_users,
            tenancy_id
        ).data
        
        for user in users:
            if user.lifecycle_state != "ACTIVE":
                continue
            
            # Check if user can log in to console
            if user.is_mfa_activated is False:
                # Check if user has console password
                try:
                    ui_pwd = identity_client.get_user_ui_password_information(user.id).data
                    if ui_pwd and ui_pwd.lifecycle_state == "ACTIVE":
                        users_without_mfa.append(user.name)
                except:
                    pass  # No console password
        
        if users_without_mfa:
            findings.append({
                "check_id": "1.7",
                "status": "FAIL",
                "resource": "IAM Users",
                "detail": f"{len(users_without_mfa)} users with console access lack MFA: {', '.join(users_without_mfa[:10])}" + 
                          ("..." if len(users_without_mfa) > 10 else "")
            })
        else:
            findings.append({
                "check_id": "1.7",
                "status": "PASS",
                "resource": "IAM Users",
                "detail": "All users with console access have MFA enabled"
            })
            
    except Exception as e:
        findings.append({
            "check_id": "1.7",
            "status": "ERROR",
            "resource": "IAM Users",
            "detail": f"Could not check MFA status: {str(e)}"
        })
    
    return findings


def check_api_key_rotation(identity_client, tenancy_id, max_age_days=90):
    """Check API keys rotate within 90 days (CIS 1.8)."""
    findings = []
    old_keys = []
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=max_age_days)
    
    try:
        users = oci.pagination.list_call_get_all_results(
            identity_client.list_users,
            tenancy_id
        ).data
        
        for user in users:
            if user.lifecycle_state != "ACTIVE":
                continue
            
            try:
                api_keys = identity_client.list_api_keys(user.id).data
                for key in api_keys:
                    if key.lifecycle_state == "ACTIVE":
                        key_created = key.time_created.replace(tzinfo=timezone.utc)
                        if key_created < cutoff_date:
                            age_days = (datetime.now(timezone.utc) - key_created).days
                            old_keys.append(f"{user.name} (key: {key.fingerprint[:20]}..., age: {age_days} days)")
            except:
                pass
        
        if old_keys:
            findings.append({
                "check_id": "1.8",
                "status": "FAIL",
                "resource": "API Keys",
                "detail": f"{len(old_keys)} API keys older than {max_age_days} days: {'; '.join(old_keys[:5])}" +
                          ("..." if len(old_keys) > 5 else "")
            })
        else:
            findings.append({
                "check_id": "1.8",
                "status": "PASS",
                "resource": "API Keys",
                "detail": f"All API keys are less than {max_age_days} days old"
            })
            
    except Exception as e:
        findings.append({
            "check_id": "1.8",
            "status": "ERROR",
            "resource": "API Keys",
            "detail": f"Could not check API key rotation: {str(e)}"
        })
    
    return findings


def check_security_lists(network_client, compartments):
    """Check security lists for unrestricted access (CIS 2.1, 2.2)."""
    findings = []
    ssh_violations = []
    rdp_violations = []
    
    for comp in compartments:
        try:
            security_lists = oci.pagination.list_call_get_all_results(
                network_client.list_security_lists,
                comp["id"]
            ).data
            
            for sl in security_lists:
                if sl.lifecycle_state != "AVAILABLE":
                    continue
                    
                for rule in sl.ingress_security_rules or []:
                    source = rule.source
                    if source not in ["0.0.0.0/0", "::/0"]:
                        continue
                    
                    # Check for SSH (port 22)
                    if rule.tcp_options:
                        min_port = rule.tcp_options.destination_port_range.min if rule.tcp_options.destination_port_range else 1
                        max_port = rule.tcp_options.destination_port_range.max if rule.tcp_options.destination_port_range else 65535
                        
                        if min_port <= 22 <= max_port:
                            ssh_violations.append(f"{sl.display_name} in {comp['name']}")
                        if min_port <= 3389 <= max_port:
                            rdp_violations.append(f"{sl.display_name} in {comp['name']}")
                    
                    # Check if all protocols allowed (no tcp_options = all traffic)
                    if rule.protocol == "all" or (not rule.tcp_options and not rule.udp_options):
                        ssh_violations.append(f"{sl.display_name} in {comp['name']} (all traffic)")
                        rdp_violations.append(f"{sl.display_name} in {comp['name']} (all traffic)")
                        
        except Exception as e:
            logger.warning(f"Error checking security lists in {comp['name']}: {e}")
    
    # CIS 2.1 - SSH
    if ssh_violations:
        findings.append({
            "check_id": "2.1",
            "status": "FAIL",
            "resource": "Security Lists",
            "detail": f"{len(set(ssh_violations))} security lists allow SSH from 0.0.0.0/0: {', '.join(list(set(ssh_violations))[:5])}"
        })
    else:
        findings.append({
            "check_id": "2.1",
            "status": "PASS",
            "resource": "Security Lists",
            "detail": "No security lists allow SSH from 0.0.0.0/0"
        })
    
    # CIS 2.2 - RDP
    if rdp_violations:
        findings.append({
            "check_id": "2.2",
            "status": "FAIL",
            "resource": "Security Lists",
            "detail": f"{len(set(rdp_violations))} security lists allow RDP from 0.0.0.0/0"
        })
    else:
        findings.append({
            "check_id": "2.2",
            "status": "PASS",
            "resource": "Security Lists",
            "detail": "No security lists allow RDP from 0.0.0.0/0"
        })
    
    return findings


def check_nsg_rules(network_client, compartments):
    """Check network security groups for unrestricted access (CIS 2.3, 2.4)."""
    findings = []
    ssh_violations = []
    rdp_violations = []
    
    for comp in compartments:
        try:
            nsgs = oci.pagination.list_call_get_all_results(
                network_client.list_network_security_groups,
                comp["id"]
            ).data
            
            for nsg in nsgs:
                if nsg.lifecycle_state != "AVAILABLE":
                    continue
                
                rules = oci.pagination.list_call_get_all_results(
                    network_client.list_network_security_group_security_rules,
                    nsg.id,
                    direction="INGRESS"
                ).data
                
                for rule in rules:
                    source = rule.source
                    if source not in ["0.0.0.0/0", "::/0"]:
                        continue
                    
                    if rule.tcp_options:
                        min_port = rule.tcp_options.destination_port_range.min if rule.tcp_options.destination_port_range else 1
                        max_port = rule.tcp_options.destination_port_range.max if rule.tcp_options.destination_port_range else 65535
                        
                        if min_port <= 22 <= max_port:
                            ssh_violations.append(f"{nsg.display_name} in {comp['name']}")
                        if min_port <= 3389 <= max_port:
                            rdp_violations.append(f"{nsg.display_name} in {comp['name']}")
                    
                    if rule.protocol == "all":
                        ssh_violations.append(f"{nsg.display_name} in {comp['name']} (all)")
                        rdp_violations.append(f"{nsg.display_name} in {comp['name']} (all)")
                        
        except Exception as e:
            logger.warning(f"Error checking NSGs in {comp['name']}: {e}")
    
    # CIS 2.3 - SSH via NSG
    if ssh_violations:
        findings.append({
            "check_id": "2.3",
            "status": "FAIL",
            "resource": "Network Security Groups",
            "detail": f"{len(set(ssh_violations))} NSGs allow SSH from 0.0.0.0/0"
        })
    else:
        findings.append({
            "check_id": "2.3",
            "status": "PASS",
            "resource": "Network Security Groups",
            "detail": "No NSGs allow SSH from 0.0.0.0/0"
        })
    
    # CIS 2.4 - RDP via NSG
    if rdp_violations:
        findings.append({
            "check_id": "2.4",
            "status": "FAIL",
            "resource": "Network Security Groups",
            "detail": f"{len(set(rdp_violations))} NSGs allow RDP from 0.0.0.0/0"
        })
    else:
        findings.append({
            "check_id": "2.4",
            "status": "PASS",
            "resource": "Network Security Groups",
            "detail": "No NSGs allow RDP from 0.0.0.0/0"
        })
    
    return findings


def check_audit_retention(audit_client, tenancy_id):
    """Check audit log retention is set to 365 days (CIS 3.1)."""
    findings = []
    
    try:
        config = audit_client.get_configuration(tenancy_id).data
        retention_days = config.retention_period_days
        
        if retention_days < 365:
            findings.append({
                "check_id": "3.1",
                "status": "FAIL",
                "resource": "Audit Configuration",
                "detail": f"Audit retention is {retention_days} days, should be at least 365"
            })
        else:
            findings.append({
                "check_id": "3.1",
                "status": "PASS",
                "resource": "Audit Configuration",
                "detail": f"Audit retention is {retention_days} days"
            })
            
    except Exception as e:
        findings.append({
            "check_id": "3.1",
            "status": "ERROR",
            "resource": "Audit Configuration",
            "detail": f"Could not check audit retention: {str(e)}"
        })
    
    return findings


def check_cloud_guard(cloud_guard_client, tenancy_id):
    """Check Cloud Guard is enabled (CIS 3.15)."""
    findings = []
    
    try:
        status = cloud_guard_client.get_configuration(tenancy_id).data
        
        if status.status == "ENABLED":
            findings.append({
                "check_id": "3.15",
                "status": "PASS",
                "resource": "Cloud Guard",
                "detail": f"Cloud Guard is enabled (reporting region: {status.reporting_region})"
            })
        else:
            findings.append({
                "check_id": "3.15",
                "status": "FAIL",
                "resource": "Cloud Guard",
                "detail": "Cloud Guard is not enabled"
            })
            
    except Exception as e:
        findings.append({
            "check_id": "3.15",
            "status": "FAIL",
            "resource": "Cloud Guard",
            "detail": f"Cloud Guard check failed (likely not enabled): {str(e)}"
        })
    
    return findings


def check_public_buckets(object_storage_client, compartments, namespace):
    """Check for publicly accessible buckets (CIS 4.1.1)."""
    findings = []
    public_buckets = []
    
    for comp in compartments:
        try:
            buckets = object_storage_client.list_buckets(namespace, comp["id"]).data
            
            for bucket_summary in buckets:
                try:
                    bucket = object_storage_client.get_bucket(namespace, bucket_summary.name).data
                    if bucket.public_access_type != "NoPublicAccess":
                        public_buckets.append(f"{bucket.name} ({bucket.public_access_type})")
                except:
                    pass
                    
        except Exception as e:
            logger.warning(f"Error checking buckets in {comp['name']}: {e}")
    
    if public_buckets:
        findings.append({
            "check_id": "4.1.1",
            "status": "FAIL",
            "resource": "Object Storage Buckets",
            "detail": f"{len(public_buckets)} public buckets found: {', '.join(public_buckets[:5])}"
        })
    else:
        findings.append({
            "check_id": "4.1.1",
            "status": "PASS",
            "resource": "Object Storage Buckets",
            "detail": "No publicly accessible buckets found"
        })
    
    return findings


def check_bucket_encryption(object_storage_client, compartments, namespace):
    """Check buckets are encrypted with CMK (CIS 4.1.2)."""
    findings = []
    unencrypted_buckets = []
    
    for comp in compartments:
        try:
            buckets = object_storage_client.list_buckets(namespace, comp["id"]).data
            
            for bucket_summary in buckets:
                try:
                    bucket = object_storage_client.get_bucket(namespace, bucket_summary.name).data
                    if not bucket.kms_key_id:
                        unencrypted_buckets.append(bucket.name)
                except:
                    pass
                    
        except Exception as e:
            logger.warning(f"Error checking bucket encryption in {comp['name']}: {e}")
    
    if unencrypted_buckets:
        findings.append({
            "check_id": "4.1.2",
            "status": "FAIL",
            "resource": "Object Storage Buckets",
            "detail": f"{len(unencrypted_buckets)} buckets not using CMK encryption: {', '.join(unencrypted_buckets[:5])}"
        })
    else:
        findings.append({
            "check_id": "4.1.2",
            "status": "PASS",
            "resource": "Object Storage Buckets",
            "detail": "All buckets use CMK encryption"
        })
    
    return findings


def check_vcn_flow_logs(logging_client, network_client, compartments):
    """Check VCN flow logging is enabled for all subnets (CIS 3.14)."""
    findings = []
    subnets_without_flow_logs = []
    total_subnets = 0
    
    for comp in compartments:
        try:
            subnets = oci.pagination.list_call_get_all_results(
                network_client.list_subnets,
                comp["id"]
            ).data
            
            for subnet in subnets:
                if subnet.lifecycle_state != "AVAILABLE":
                    continue
                total_subnets += 1
                
                # Check if subnet has flow logs enabled
                try:
                    logs = oci.pagination.list_call_get_all_results(
                        logging_client.list_logs,
                        comp["id"]  # Log groups are at compartment level
                    ).data
                    
                    has_flow_log = False
                    for log in logs:
                        if (log.configuration and 
                            log.configuration.source and
                            log.configuration.source.service == "flowlogs" and
                            log.configuration.source.resource == subnet.id):
                            has_flow_log = True
                            break
                    
                    if not has_flow_log:
                        subnets_without_flow_logs.append(f"{subnet.display_name}")
                except:
                    subnets_without_flow_logs.append(f"{subnet.display_name}")
                    
        except Exception as e:
            logger.warning(f"Error checking flow logs in {comp['name']}: {e}")
    
    if subnets_without_flow_logs:
        findings.append({
            "check_id": "3.14",
            "status": "FAIL",
            "resource": "VCN Subnets",
            "detail": f"{len(subnets_without_flow_logs)}/{total_subnets} subnets lack flow logging"
        })
    else:
        findings.append({
            "check_id": "3.14",
            "status": "PASS",
            "resource": "VCN Subnets",
            "detail": f"All {total_subnets} subnets have flow logging enabled"
        })
    
    return findings


def check_root_compartment_resources(compute_client, tenancy_id):
    """Check no resources are created in root compartment (CIS 5.2)."""
    findings = []
    root_resources = []
    
    try:
        # Check for instances in root
        instances = compute_client.list_instances(tenancy_id).data
        for instance in instances:
            if instance.lifecycle_state not in ["TERMINATED", "TERMINATING"]:
                root_resources.append(f"Instance: {instance.display_name}")
        
        if root_resources:
            findings.append({
                "check_id": "5.2",
                "status": "FAIL",
                "resource": "Root Compartment",
                "detail": f"{len(root_resources)} resources in root compartment: {', '.join(root_resources[:5])}"
            })
        else:
            findings.append({
                "check_id": "5.2",
                "status": "PASS",
                "resource": "Root Compartment",
                "detail": "No compute resources in root compartment"
            })
            
    except Exception as e:
        findings.append({
            "check_id": "5.2",
            "status": "ERROR",
            "resource": "Root Compartment",
            "detail": f"Could not check root compartment resources: {str(e)}"
        })
    
    return findings


def run_cis_scan(region=None):
    """Run all CIS benchmark checks and return findings."""
    logger.info("Starting CIS benchmark scan...")
    
    # Initialize signer
    signer = get_resource_principal_signer()
    
    # Get tenancy ID from signer
    tenancy_id = signer.tenancy_id
    logger.info(f"Scanning tenancy: {tenancy_id}")
    
    # Determine region
    if not region:
        region = signer.region
    
    logger.info(f"Using region: {region}")
    
    # Initialize clients
    identity_client = oci.identity.IdentityClient(config={}, signer=signer)
    identity_client.base_client.set_region(region)
    
    network_client = oci.core.VirtualNetworkClient(config={}, signer=signer)
    network_client.base_client.set_region(region)
    
    compute_client = oci.core.ComputeClient(config={}, signer=signer)
    compute_client.base_client.set_region(region)
    
    audit_client = oci.audit.AuditClient(config={}, signer=signer)
    audit_client.base_client.set_region(region)
    
    object_storage_client = oci.object_storage.ObjectStorageClient(config={}, signer=signer)
    object_storage_client.base_client.set_region(region)
    
    logging_client = oci.logging.LoggingManagementClient(config={}, signer=signer)
    logging_client.base_client.set_region(region)
    
    cloud_guard_client = oci.cloud_guard.CloudGuardClient(config={}, signer=signer)
    cloud_guard_client.base_client.set_region(region)
    
    # Get namespace for object storage
    namespace = object_storage_client.get_namespace().data
    
    # Get all compartments
    compartments = get_all_compartments(identity_client, tenancy_id)
    logger.info(f"Found {len(compartments)} compartments")
    
    # Run all checks
    all_findings = []
    
    # Section 1: IAM
    logger.info("Checking Section 1: Identity and Access Management...")
    all_findings.extend(check_iam_password_policy(identity_client, tenancy_id))
    all_findings.extend(check_mfa_status(identity_client, tenancy_id))
    all_findings.extend(check_api_key_rotation(identity_client, tenancy_id))
    
    # Section 2: Networking
    logger.info("Checking Section 2: Networking...")
    all_findings.extend(check_security_lists(network_client, compartments))
    all_findings.extend(check_nsg_rules(network_client, compartments))
    
    # Section 3: Logging and Monitoring
    logger.info("Checking Section 3: Logging and Monitoring...")
    all_findings.extend(check_audit_retention(audit_client, tenancy_id))
    all_findings.extend(check_cloud_guard(cloud_guard_client, tenancy_id))
    all_findings.extend(check_vcn_flow_logs(logging_client, network_client, compartments))
    
    # Section 4: Object Storage
    logger.info("Checking Section 4: Object Storage...")
    all_findings.extend(check_public_buckets(object_storage_client, compartments, namespace))
    all_findings.extend(check_bucket_encryption(object_storage_client, compartments, namespace))
    
    # Section 5: Asset Management
    logger.info("Checking Section 5: Asset Management...")
    all_findings.extend(check_root_compartment_resources(compute_client, tenancy_id))
    
    # Generate summary
    summary = {
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "tenancy_id": tenancy_id,
        "region": region,
        "compartments_scanned": len(compartments),
        "total_checks": len(all_findings),
        "passed": len([f for f in all_findings if f["status"] == "PASS"]),
        "failed": len([f for f in all_findings if f["status"] == "FAIL"]),
        "errors": len([f for f in all_findings if f["status"] == "ERROR"])
    }
    
    logger.info(f"Scan complete: {summary['passed']} passed, {summary['failed']} failed, {summary['errors']} errors")
    
    return {
        "summary": summary,
        "findings": all_findings,
        "cis_checks": CIS_CHECKS
    }


def handler(ctx, data: io.BytesIO = None):
    """OCI Function handler - entry point for HTTP triggers."""
    try:
        # Validate API key from header (forwarded by API Gateway)
        incoming_headers = ctx.Headers() if hasattr(ctx, 'Headers') else {}
        
        # Check x-api-key header (case-insensitive lookup)
        api_key = None
        for header_name, header_value in incoming_headers.items():
            if header_name.lower() == "x-api-key":
                api_key = header_value[0] if isinstance(header_value, list) else header_value
                break
        
        # Also check the x-expected-api-key header set by API Gateway
        expected_key = None
        for header_name, header_value in incoming_headers.items():
            if header_name.lower() == "x-expected-api-key":
                expected_key = header_value[0] if isinstance(header_value, list) else header_value
                break
        
        # Validate API key if configured
        if EXPECTED_API_KEY:
            if not api_key or api_key != EXPECTED_API_KEY:
                logger.warning(f"Invalid or missing API key")
                return response.Response(
                    ctx,
                    response_data=json.dumps({"error": "Unauthorized - Invalid API key"}),
                    headers={"Content-Type": "application/json"},
                    status_code=401
                )
        elif expected_key:
            # Validate against the key passed by API Gateway
            if not api_key or api_key != expected_key:
                logger.warning(f"Invalid or missing API key")
                return response.Response(
                    ctx,
                    response_data=json.dumps({"error": "Unauthorized - Invalid API key"}),
                    headers={"Content-Type": "application/json"},
                    status_code=401
                )
        
        # Parse request body if present
        body = {}
        try:
            body = json.loads(data.getvalue())
        except:
            pass
        
        # Get optional region override
        region = body.get("region")
        
        # Run the scan
        result = run_cis_scan(region=region)
        
        return response.Response(
            ctx,
            response_data=json.dumps(result, indent=2),
            headers={"Content-Type": "application/json"}
        )
        
    except Exception as e:
        logger.error(f"Function error: {str(e)}")
        return response.Response(
            ctx,
            response_data=json.dumps({
                "error": str(e),
                "status": "failed"
            }),
            headers={"Content-Type": "application/json"},
            status_code=500
        )