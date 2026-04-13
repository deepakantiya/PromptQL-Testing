import executor
#!/usr/bin/env python3
"""
OCI CIS Benchmark Scanner
=========================
Scans Oracle Cloud Infrastructure for CIS Benchmark compliance.
Based on CIS Oracle Cloud Infrastructure Foundations Benchmark v2.0

Usage:
  1. Install OCI Python SDK: pip install oci
  2. Configure OCI CLI: oci setup config
  3. Run: python oci_cis_scanner.py

The script will scan your entire OCI tenancy and flag misconfigurations.
"""

import json
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

# ============================================================================
# Configuration - Update these values before running
# ============================================================================
# Leave as None to use default OCI config file (~/.oci/config)
OCI_CONFIG_FILE = None
OCI_CONFIG_PROFILE = "DEFAULT"

# ============================================================================
# Data Models
# ============================================================================

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class Status(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    MANUAL = "MANUAL_CHECK"
    ERROR = "ERROR"

@dataclass
class Finding:
    cis_control: str
    title: str
    status: Status
    severity: Severity
    description: str
    resource_id: Optional[str] = None
    resource_name: Optional[str] = None
    compartment: Optional[str] = None
    recommendation: str = ""
    details: dict = field(default_factory=dict)

# ============================================================================
# CIS Benchmark Checks
# ============================================================================

class CISScanner:
    def __init__(self, config, signer=None):
        import oci
        self.config = config
        self.signer = signer
        self.findings = []
        
        # Initialize clients
        if signer:
            self.identity = oci.identity.IdentityClient(config={}, signer=signer)
            self.audit = oci.audit.AuditClient(config={}, signer=signer)
            self.core = oci.core.VirtualNetworkClient(config={}, signer=signer)
            self.compute = oci.core.ComputeClient(config={}, signer=signer)
            self.object_storage = oci.object_storage.ObjectStorageClient(config={}, signer=signer)
            self.logging = oci.logging.LoggingManagementClient(config={}, signer=signer)
            self.cloud_guard = oci.cloud_guard.CloudGuardClient(config={}, signer=signer)
            self.events = oci.events.EventsClient(config={}, signer=signer)
            self.kms = oci.key_management.KmsVaultClient(config={}, signer=signer)
            self.ons = oci.ons.NotificationControlPlaneClient(config={}, signer=signer)
        else:
            self.identity = oci.identity.IdentityClient(config)
            self.audit = oci.audit.AuditClient(config)
            self.core = oci.core.VirtualNetworkClient(config)
            self.compute = oci.core.ComputeClient(config)
            self.object_storage = oci.object_storage.ObjectStorageClient(config)
            self.logging = oci.logging.LoggingManagementClient(config)
            self.cloud_guard = oci.cloud_guard.CloudGuardClient(config)
            self.events = oci.events.EventsClient(config)
            self.kms = oci.key_management.KmsVaultClient(config)
            self.ons = oci.ons.NotificationControlPlaneClient(config)
        
        self.tenancy_id = config.get("tenancy")
    
    def add_finding(self, finding: Finding):
        self.findings.append(finding)
        status_icon = "✅" if finding.status == Status.PASS else "❌" if finding.status == Status.FAIL else "⚠️"
        print(f"  {status_icon} [{finding.cis_control}] {finding.title}: {finding.status.value}")
    
    def get_all_compartments(self):
        """Get all compartments in the tenancy"""
        import oci
        compartments = [oci.identity.models.Compartment(
            id=self.tenancy_id,
            name="root",
            compartment_id=self.tenancy_id,
            lifecycle_state="ACTIVE"
        )]
        
        try:
            response = oci.pagination.list_call_get_all_results(
                self.identity.list_compartments,
                self.tenancy_id,
                compartment_id_in_subtree=True,
                lifecycle_state="ACTIVE"
            )
            compartments.extend(response.data)
        except Exception as e:
            print(f"  Warning: Could not list compartments: {e}")
        
        return compartments

    # ========================================================================
    # Section 1: Identity and Access Management
    # ========================================================================
    
    def check_1_1_service_level_admins(self):
        """CIS 1.1 - Ensure service level admins are created"""
        try:
            policies = oci.pagination.list_call_get_all_results(
                self.identity.list_policies,
                self.tenancy_id
            ).data
            
            admin_policies = [p for p in policies if "manage all-resources" in str(p.statements).lower()]
            
            if len(admin_policies) <= 1:
                self.add_finding(Finding(
                    cis_control="1.1",
                    title="Service Level Admins",
                    status=Status.WARNING,
                    severity=Severity.MEDIUM,
                    description="Limited admin policies found. Verify service-level admins are configured.",
                    recommendation="Create service-level admin policies instead of tenancy-wide admin access."
                ))
            else:
                self.add_finding(Finding(
                    cis_control="1.1",
                    title="Service Level Admins",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    description="Multiple admin policies found, suggesting service-level separation."
                ))
        except Exception as e:
            self.add_finding(Finding(
                cis_control="1.1",
                title="Service Level Admins",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                description=f"Error checking admin policies: {str(e)}"
            ))
    
    def check_1_2_mfa_enabled(self):
        """CIS 1.2 - Ensure MFA is enabled for all users"""
        import oci
        try:
            users = oci.pagination.list_call_get_all_results(
                self.identity.list_users,
                self.tenancy_id
            ).data
            
            users_without_mfa = []
            for user in users:
                if user.lifecycle_state == "ACTIVE":
                    mfa_devices = self.identity.list_mfa_totp_devices(user.id).data
                    if not mfa_devices:
                        users_without_mfa.append(user.name)
            
            if users_without_mfa:
                self.add_finding(Finding(
                    cis_control="1.2",
                    title="MFA Enabled for Users",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    description=f"{len(users_without_mfa)} users do not have MFA enabled.",
                    details={"users_without_mfa": users_without_mfa[:20]},  # Limit to 20
                    recommendation="Enable MFA for all user accounts."
                ))
            else:
                self.add_finding(Finding(
                    cis_control="1.2",
                    title="MFA Enabled for Users",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    description="All active users have MFA enabled."
                ))
        except Exception as e:
            self.add_finding(Finding(
                cis_control="1.2",
                title="MFA Enabled for Users",
                status=Status.ERROR,
                severity=Severity.HIGH,
                description=f"Error checking MFA status: {str(e)}"
            ))
    
    def check_1_3_api_keys_rotation(self):
        """CIS 1.3 - Ensure API keys are rotated within 90 days"""
        import oci
        try:
            users = oci.pagination.list_call_get_all_results(
                self.identity.list_users,
                self.tenancy_id
            ).data
            
            old_keys = []
            ninety_days_ago = datetime.utcnow() - timedelta(days=90)
            
            for user in users:
                if user.lifecycle_state == "ACTIVE":
                    api_keys = self.identity.list_api_keys(user.id).data
                    for key in api_keys:
                        if key.lifecycle_state == "ACTIVE":
                            if key.time_created.replace(tzinfo=None) < ninety_days_ago:
                                old_keys.append({
                                    "user": user.name,
                                    "key_fingerprint": key.fingerprint,
                                    "created": str(key.time_created)
                                })
            
            if old_keys:
                self.add_finding(Finding(
                    cis_control="1.3",
                    title="API Keys Rotation",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    description=f"{len(old_keys)} API keys are older than 90 days.",
                    details={"old_keys": old_keys[:10]},
                    recommendation="Rotate API keys that are older than 90 days."
                ))
            else:
                self.add_finding(Finding(
                    cis_control="1.3",
                    title="API Keys Rotation",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    description="All API keys have been rotated within 90 days."
                ))
        except Exception as e:
            self.add_finding(Finding(
                cis_control="1.3",
                title="API Keys Rotation",
                status=Status.ERROR,
                severity=Severity.HIGH,
                description=f"Error checking API key rotation: {str(e)}"
            ))
    
    def check_1_4_auth_token_rotation(self):
        """CIS 1.4 - Ensure auth tokens are rotated within 90 days"""
        import oci
        try:
            users = oci.pagination.list_call_get_all_results(
                self.identity.list_users,
                self.tenancy_id
            ).data
            
            old_tokens = []
            ninety_days_ago = datetime.utcnow() - timedelta(days=90)
            
            for user in users:
                if user.lifecycle_state == "ACTIVE":
                    auth_tokens = self.identity.list_auth_tokens(user.id).data
                    for token in auth_tokens:
                        if token.lifecycle_state == "ACTIVE":
                            if token.time_created.replace(tzinfo=None) < ninety_days_ago:
                                old_tokens.append({
                                    "user": user.name,
                                    "token_description": token.description,
                                    "created": str(token.time_created)
                                })
            
            if old_tokens:
                self.add_finding(Finding(
                    cis_control="1.4",
                    title="Auth Token Rotation",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    description=f"{len(old_tokens)} auth tokens are older than 90 days.",
                    details={"old_tokens": old_tokens[:10]},
                    recommendation="Rotate auth tokens that are older than 90 days."
                ))
            else:
                self.add_finding(Finding(
                    cis_control="1.4",
                    title="Auth Token Rotation",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    description="All auth tokens have been rotated within 90 days."
                ))
        except Exception as e:
            self.add_finding(Finding(
                cis_control="1.4",
                title="Auth Token Rotation",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                description=f"Error checking auth token rotation: {str(e)}"
            ))
    
    def check_1_5_customer_secret_keys_rotation(self):
        """CIS 1.5 - Ensure customer secret keys are rotated within 90 days"""
        import oci
        try:
            users = oci.pagination.list_call_get_all_results(
                self.identity.list_users,
                self.tenancy_id
            ).data
            
            old_keys = []
            ninety_days_ago = datetime.utcnow() - timedelta(days=90)
            
            for user in users:
                if user.lifecycle_state == "ACTIVE":
                    secret_keys = self.identity.list_customer_secret_keys(user.id).data
                    for key in secret_keys:
                        if key.lifecycle_state == "ACTIVE":
                            if key.time_created.replace(tzinfo=None) < ninety_days_ago:
                                old_keys.append({
                                    "user": user.name,
                                    "key_id": key.id,
                                    "created": str(key.time_created)
                                })
            
            if old_keys:
                self.add_finding(Finding(
                    cis_control="1.5",
                    title="Customer Secret Keys Rotation",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    description=f"{len(old_keys)} customer secret keys are older than 90 days.",
                    details={"old_keys": old_keys[:10]},
                    recommendation="Rotate customer secret keys that are older than 90 days."
                ))
            else:
                self.add_finding(Finding(
                    cis_control="1.5",
                    title="Customer Secret Keys Rotation",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    description="All customer secret keys have been rotated within 90 days."
                ))
        except Exception as e:
            self.add_finding(Finding(
                cis_control="1.5",
                title="Customer Secret Keys Rotation",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                description=f"Error checking customer secret key rotation: {str(e)}"
            ))
    
    def check_1_6_password_policy(self):
        """CIS 1.6 - Ensure password policy is configured"""
        try:
            auth_policy = self.identity.get_authentication_policy(self.tenancy_id).data
            
            issues = []
            pw_policy = auth_policy.password_policy
            
            if pw_policy.minimum_password_length < 14:
                issues.append(f"Minimum password length is {pw_policy.minimum_password_length} (should be ≥14)")
            if not pw_policy.is_numeric_characters_required:
                issues.append("Numeric characters not required")
            if not pw_policy.is_special_characters_required:
                issues.append("Special characters not required")
            if not pw_policy.is_uppercase_characters_required:
                issues.append("Uppercase characters not required")
            if not pw_policy.is_lowercase_characters_required:
                issues.append("Lowercase characters not required")
            
            if issues:
                self.add_finding(Finding(
                    cis_control="1.6",
                    title="Password Policy",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    description="Password policy does not meet CIS requirements.",
                    details={"issues": issues},
                    recommendation="Update password policy to require: min 14 chars, uppercase, lowercase, numbers, special chars."
                ))
            else:
                self.add_finding(Finding(
                    cis_control="1.6",
                    title="Password Policy",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    description="Password policy meets CIS requirements."
                ))
        except Exception as e:
            self.add_finding(Finding(
                cis_control="1.6",
                title="Password Policy",
                status=Status.ERROR,
                severity=Severity.HIGH,
                description=f"Error checking password policy: {str(e)}"
            ))
    
    def check_1_7_local_admin_users(self):
        """CIS 1.7 - Ensure IAM administrators cannot update tenancy Administrators group"""
        try:
            policies = oci.pagination.list_call_get_all_results(
                self.identity.list_policies,
                self.tenancy_id
            ).data
            
            risky_policies = []
            for policy in policies:
                for statement in policy.statements:
                    stmt_lower = statement.lower()
                    if "administrators" in stmt_lower and ("manage" in stmt_lower or "use" in stmt_lower):
                        if "groups" in stmt_lower or "users" in stmt_lower:
                            risky_policies.append({
                                "policy_name": policy.name,
                                "statement": statement
                            })
            
            if risky_policies:
                self.add_finding(Finding(
                    cis_control="1.7",
                    title="Admin Group Protection",
                    status=Status.WARNING,
                    severity=Severity.HIGH,
                    description="Policies found that may allow modifying the Administrators group.",
                    details={"risky_policies": risky_policies[:5]},
                    recommendation="Review and restrict policies that can modify the Administrators group."
                ))
            else:
                self.add_finding(Finding(
                    cis_control="1.7",
                    title="Admin Group Protection",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    description="No risky policies found for Administrators group."
                ))
        except Exception as e:
            self.add_finding(Finding(
                cis_control="1.7",
                title="Admin Group Protection",
                status=Status.ERROR,
                severity=Severity.HIGH,
                description=f"Error checking admin policies: {str(e)}"
            ))

    # ========================================================================
    # Section 2: Networking
    # ========================================================================
    
    def check_2_1_default_security_list(self):
        """CIS 2.1 - Ensure no security lists allow unrestricted ingress from 0.0.0.0/0"""
        import oci
        try:
            compartments = self.get_all_compartments()
            risky_security_lists = []
            
            for compartment in compartments:
                try:
                    vcns = oci.pagination.list_call_get_all_results(
                        self.core.list_vcns,
                        compartment.id
                    ).data
                    
                    for vcn in vcns:
                        security_lists = oci.pagination.list_call_get_all_results(
                            self.core.list_security_lists,
                            compartment.id,
                            vcn_id=vcn.id
                        ).data
                        
                        for sl in security_lists:
                            if sl.lifecycle_state == "AVAILABLE":
                                for rule in sl.ingress_security_rules or []:
                                    if rule.source == "0.0.0.0/0":
                                        if rule.protocol == "all" or (hasattr(rule, 'tcp_options') and rule.tcp_options is None):
                                            risky_security_lists.append({
                                                "vcn": vcn.display_name,
                                                "security_list": sl.display_name,
                                                "compartment": compartment.name,
                                                "protocol": rule.protocol
                                            })
                except Exception:
                    continue
            
            if risky_security_lists:
                self.add_finding(Finding(
                    cis_control="2.1",
                    title="Security Lists - Unrestricted Ingress",
                    status=Status.FAIL,
                    severity=Severity.CRITICAL,
                    description=f"{len(risky_security_lists)} security lists allow unrestricted ingress from 0.0.0.0/0.",
                    details={"risky_lists": risky_security_lists[:10]},
                    recommendation="Remove or restrict ingress rules that allow traffic from 0.0.0.0/0."
                ))
            else:
                self.add_finding(Finding(
                    cis_control="2.1",
                    title="Security Lists - Unrestricted Ingress",
                    status=Status.PASS,
                    severity=Severity.CRITICAL,
                    description="No security lists with unrestricted ingress from 0.0.0.0/0."
                ))
        except Exception as e:
            self.add_finding(Finding(
                cis_control="2.1",
                title="Security Lists - Unrestricted Ingress",
                status=Status.ERROR,
                severity=Severity.CRITICAL,
                description=f"Error checking security lists: {str(e)}"
            ))
    
    def check_2_2_ssh_restricted(self):
        """CIS 2.2 - Ensure no security lists allow ingress from 0.0.0.0/0 to port 22"""
        import oci
        try:
            compartments = self.get_all_compartments()
            risky_rules = []
            
            for compartment in compartments:
                try:
                    vcns = oci.pagination.list_call_get_all_results(
                        self.core.list_vcns,
                        compartment.id
                    ).data
                    
                    for vcn in vcns:
                        security_lists = oci.pagination.list_call_get_all_results(
                            self.core.list_security_lists,
                            compartment.id,
                            vcn_id=vcn.id
                        ).data
                        
                        for sl in security_lists:
                            if sl.lifecycle_state == "AVAILABLE":
                                for rule in sl.ingress_security_rules or []:
                                    if rule.source == "0.0.0.0/0" and rule.protocol == "6":  # TCP
                                        if hasattr(rule, 'tcp_options') and rule.tcp_options:
                                            dst_range = rule.tcp_options.destination_port_range
                                            if dst_range:
                                                if dst_range.min <= 22 <= dst_range.max:
                                                    risky_rules.append({
                                                        "vcn": vcn.display_name,
                                                        "security_list": sl.display_name,
                                                        "compartment": compartment.name
                                                    })
                except Exception:
                    continue
            
            if risky_rules:
                self.add_finding(Finding(
                    cis_control="2.2",
                    title="SSH Access Restricted",
                    status=Status.FAIL,
                    severity=Severity.CRITICAL,
                    description=f"{len(risky_rules)} security lists allow SSH (port 22) from 0.0.0.0/0.",
                    details={"risky_rules": risky_rules[:10]},
                    recommendation="Restrict SSH access to specific trusted IP ranges."
                ))
            else:
                self.add_finding(Finding(
                    cis_control="2.2",
                    title="SSH Access Restricted",
                    status=Status.PASS,
                    severity=Severity.CRITICAL,
                    description="No security lists allow unrestricted SSH access from 0.0.0.0/0."
                ))
        except Exception as e:
            self.add_finding(Finding(
                cis_control="2.2",
                title="SSH Access Restricted",
                status=Status.ERROR,
                severity=Severity.CRITICAL,
                description=f"Error checking SSH rules: {str(e)}"
            ))
    
    def check_2_3_rdp_restricted(self):
        """CIS 2.3 - Ensure no security lists allow ingress from 0.0.0.0/0 to port 3389"""
        import oci
        try:
            compartments = self.get_all_compartments()
            risky_rules = []
            
            for compartment in compartments:
                try:
                    vcns = oci.pagination.list_call_get_all_results(
                        self.core.list_vcns,
                        compartment.id
                    ).data
                    
                    for vcn in vcns:
                        security_lists = oci.pagination.list_call_get_all_results(
                            self.core.list_security_lists,
                            compartment.id,
                            vcn_id=vcn.id
                        ).data
                        
                        for sl in security_lists:
                            if sl.lifecycle_state == "AVAILABLE":
                                for rule in sl.ingress_security_rules or []:
                                    if rule.source == "0.0.0.0/0" and rule.protocol == "6":
                                        if hasattr(rule, 'tcp_options') and rule.tcp_options:
                                            dst_range = rule.tcp_options.destination_port_range
                                            if dst_range:
                                                if dst_range.min <= 3389 <= dst_range.max:
                                                    risky_rules.append({
                                                        "vcn": vcn.display_name,
                                                        "security_list": sl.display_name,
                                                        "compartment": compartment.name
                                                    })
                except Exception:
                    continue
            
            if risky_rules:
                self.add_finding(Finding(
                    cis_control="2.3",
                    title="RDP Access Restricted",
                    status=Status.FAIL,
                    severity=Severity.CRITICAL,
                    description=f"{len(risky_rules)} security lists allow RDP (port 3389) from 0.0.0.0/0.",
                    details={"risky_rules": risky_rules[:10]},
                    recommendation="Restrict RDP access to specific trusted IP ranges."
                ))
            else:
                self.add_finding(Finding(
                    cis_control="2.3",
                    title="RDP Access Restricted",
                    status=Status.PASS,
                    severity=Severity.CRITICAL,
                    description="No security lists allow unrestricted RDP access from 0.0.0.0/0."
                ))
        except Exception as e:
            self.add_finding(Finding(
                cis_control="2.3",
                title="RDP Access Restricted",
                status=Status.ERROR,
                severity=Severity.CRITICAL,
                description=f"Error checking RDP rules: {str(e)}"
            ))
    
    def check_2_4_nsg_unrestricted(self):
        """CIS 2.4 - Ensure NSGs don't allow unrestricted ingress"""
        import oci
        try:
            compartments = self.get_all_compartments()
            risky_nsgs = []
            
            for compartment in compartments:
                try:
                    nsgs = oci.pagination.list_call_get_all_results(
                        self.core.list_network_security_groups,
                        compartment.id
                    ).data
                    
                    for nsg in nsgs:
                        if nsg.lifecycle_state == "AVAILABLE":
                            rules = self.core.list_network_security_group_security_rules(
                                nsg.id,
                                direction="INGRESS"
                            ).data
                            
                            for rule in rules:
                                if rule.source == "0.0.0.0/0":
                                    if rule.protocol == "all":
                                        risky_nsgs.append({
                                            "nsg": nsg.display_name,
                                            "compartment": compartment.name,
                                            "protocol": "all"
                                        })
                except Exception:
                    continue
            
            if risky_nsgs:
                self.add_finding(Finding(
                    cis_control="2.4",
                    title="NSG - Unrestricted Ingress",
                    status=Status.FAIL,
                    severity=Severity.CRITICAL,
                    description=f"{len(risky_nsgs)} NSGs allow unrestricted ingress from 0.0.0.0/0.",
                    details={"risky_nsgs": risky_nsgs[:10]},
                    recommendation="Restrict NSG rules to specific ports and sources."
                ))
            else:
                self.add_finding(Finding(
                    cis_control="2.4",
                    title="NSG - Unrestricted Ingress",
                    status=Status.PASS,
                    severity=Severity.CRITICAL,
                    description="No NSGs with unrestricted ingress from 0.0.0.0/0."
                ))
        except Exception as e:
            self.add_finding(Finding(
                cis_control="2.4",
                title="NSG - Unrestricted Ingress",
                status=Status.ERROR,
                severity=Severity.CRITICAL,
                description=f"Error checking NSGs: {str(e)}"
            ))

    # ========================================================================
    # Section 3: Logging and Monitoring
    # ========================================================================
    
    def check_3_1_audit_retention(self):
        """CIS 3.1 - Ensure audit log retention period is set to 365 days"""
        try:
            audit_config = self.audit.get_configuration(self.tenancy_id).data
            
            if audit_config.retention_period_days >= 365:
                self.add_finding(Finding(
                    cis_control="3.1",
                    title="Audit Log Retention",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    description=f"Audit log retention is {audit_config.retention_period_days} days.",
                ))
            else:
                self.add_finding(Finding(
                    cis_control="3.1",
                    title="Audit Log Retention",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    description=f"Audit log retention is only {audit_config.retention_period_days} days (should be ≥365).",
                    recommendation="Set audit log retention to at least 365 days."
                ))
        except Exception as e:
            self.add_finding(Finding(
                cis_control="3.1",
                title="Audit Log Retention",
                status=Status.ERROR,
                severity=Severity.HIGH,
                description=f"Error checking audit retention: {str(e)}"
            ))
    
    def check_3_2_default_tags(self):
        """CIS 3.2 - Ensure default tags are used"""
        import oci
        try:
            tag_namespaces = oci.pagination.list_call_get_all_results(
                self.identity.list_tag_namespaces,
                self.tenancy_id
            ).data
            
            default_tags = oci.pagination.list_call_get_all_results(
                self.identity.list_tag_defaults,
                self.tenancy_id
            ).data
            
            if len(default_tags) > 0:
                self.add_finding(Finding(
                    cis_control="3.2",
                    title="Default Tags",
                    status=Status.PASS,
                    severity=Severity.LOW,
                    description=f"{len(default_tags)} default tags configured.",
                ))
            else:
                self.add_finding(Finding(
                    cis_control="3.2",
                    title="Default Tags",
                    status=Status.FAIL,
                    severity=Severity.LOW,
                    description="No default tags configured.",
                    recommendation="Configure default tags for resource tracking and cost management."
                ))
        except Exception as e:
            self.add_finding(Finding(
                cis_control="3.2",
                title="Default Tags",
                status=Status.ERROR,
                severity=Severity.LOW,
                description=f"Error checking default tags: {str(e)}"
            ))
    
    def check_3_3_notifications_for_iam_changes(self):
        """CIS 3.3 - Ensure notifications are enabled for IAM changes"""
        import oci
        try:
            compartments = self.get_all_compartments()
            iam_event_rules = []
            
            for compartment in compartments:
                try:
                    rules = oci.pagination.list_call_get_all_results(
                        self.events.list_rules,
                        compartment.id
                    ).data
                    
                    for rule in rules:
                        if rule.lifecycle_state == "ACTIVE":
                            condition = str(rule.condition).lower() if rule.condition else ""
                            if "identity" in condition or "iam" in condition:
                                iam_event_rules.append({
                                    "rule": rule.display_name,
                                    "compartment": compartment.name
                                })
                except Exception:
                    continue
            
            if iam_event_rules:
                self.add_finding(Finding(
                    cis_control="3.3",
                    title="IAM Change Notifications",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    description=f"{len(iam_event_rules)} event rules monitoring IAM changes.",
                ))
            else:
                self.add_finding(Finding(
                    cis_control="3.3",
                    title="IAM Change Notifications",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    description="No event rules found for IAM change notifications.",
                    recommendation="Create event rules to notify on IAM policy and user changes."
                ))
        except Exception as e:
            self.add_finding(Finding(
                cis_control="3.3",
                title="IAM Change Notifications",
                status=Status.ERROR,
                severity=Severity.HIGH,
                description=f"Error checking IAM notifications: {str(e)}"
            ))
    
    def check_3_4_vcn_flow_logs(self):
        """CIS 3.4 - Ensure VCN flow logs are enabled"""
        import oci
        try:
            compartments = self.get_all_compartments()
            vcns_without_flow_logs = []
            
            for compartment in compartments:
                try:
                    vcns = oci.pagination.list_call_get_all_results(
                        self.core.list_vcns,
                        compartment.id
                    ).data
                    
                    for vcn in vcns:
                        if vcn.lifecycle_state == "AVAILABLE":
                            # Check for flow logs in logging service
                            try:
                                log_groups = oci.pagination.list_call_get_all_results(
                                    self.logging.list_log_groups,
                                    compartment.id
                                ).data
                                
                                has_flow_log = False
                                for lg in log_groups:
                                    logs = oci.pagination.list_call_get_all_results(
                                        self.logging.list_logs,
                                        lg.id
                                    ).data
                                    for log in logs:
                                        if log.configuration and hasattr(log.configuration, 'source'):
                                            if hasattr(log.configuration.source, 'resource') and vcn.id in str(log.configuration.source.resource):
                                                has_flow_log = True
                                                break
                                    if has_flow_log:
                                        break
                                
                                if not has_flow_log:
                                    vcns_without_flow_logs.append({
                                        "vcn": vcn.display_name,
                                        "compartment": compartment.name
                                    })
                            except Exception:
                                pass
                except Exception:
                    continue
            
            if vcns_without_flow_logs:
                self.add_finding(Finding(
                    cis_control="3.4",
                    title="VCN Flow Logs",
                    status=Status.WARNING,
                    severity=Severity.MEDIUM,
                    description=f"{len(vcns_without_flow_logs)} VCNs may not have flow logs enabled.",
                    details={"vcns": vcns_without_flow_logs[:10]},
                    recommendation="Enable flow logs for all VCNs to monitor network traffic."
                ))
            else:
                self.add_finding(Finding(
                    cis_control="3.4",
                    title="VCN Flow Logs",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    description="VCN flow logs appear to be configured."
                ))
        except Exception as e:
            self.add_finding(Finding(
                cis_control="3.4",
                title="VCN Flow Logs",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                description=f"Error checking VCN flow logs: {str(e)}"
            ))
    
    def check_3_5_cloud_guard_enabled(self):
        """CIS 3.5 - Ensure Cloud Guard is enabled"""
        try:
            config = self.cloud_guard.get_configuration(self.tenancy_id).data
            
            if config.status == "ENABLED":
                self.add_finding(Finding(
                    cis_control="3.5",
                    title="Cloud Guard",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    description="Cloud Guard is enabled."
                ))
            else:
                self.add_finding(Finding(
                    cis_control="3.5",
                    title="Cloud Guard",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    description="Cloud Guard is not enabled.",
                    recommendation="Enable Cloud Guard for continuous security monitoring."
                ))
        except Exception as e:
            self.add_finding(Finding(
                cis_control="3.5",
                title="Cloud Guard",
                status=Status.ERROR,
                severity=Severity.HIGH,
                description=f"Error checking Cloud Guard: {str(e)}"
            ))

    # ========================================================================
    # Section 4: Object Storage
    # ========================================================================
    
    def check_4_1_public_buckets(self):
        """CIS 4.1 - Ensure no Object Storage buckets are publicly accessible"""
        import oci
        try:
            namespace = self.object_storage.get_namespace().data
            compartments = self.get_all_compartments()
            public_buckets = []
            
            for compartment in compartments:
                try:
                    buckets = oci.pagination.list_call_get_all_results(
                        self.object_storage.list_buckets,
                        namespace,
                        compartment.id
                    ).data
                    
                    for bucket in buckets:
                        bucket_details = self.object_storage.get_bucket(namespace, bucket.name).data
                        if bucket_details.public_access_type != "NoPublicAccess":
                            public_buckets.append({
                                "bucket": bucket.name,
                                "compartment": compartment.name,
                                "access_type": bucket_details.public_access_type
                            })
                except Exception:
                    continue
            
            if public_buckets:
                self.add_finding(Finding(
                    cis_control="4.1",
                    title="Public Buckets",
                    status=Status.FAIL,
                    severity=Severity.CRITICAL,
                    description=f"{len(public_buckets)} buckets are publicly accessible.",
                    details={"public_buckets": public_buckets[:10]},
                    recommendation="Remove public access from buckets unless absolutely required."
                ))
            else:
                self.add_finding(Finding(
                    cis_control="4.1",
                    title="Public Buckets",
                    status=Status.PASS,
                    severity=Severity.CRITICAL,
                    description="No publicly accessible buckets found."
                ))
        except Exception as e:
            self.add_finding(Finding(
                cis_control="4.1",
                title="Public Buckets",
                status=Status.ERROR,
                severity=Severity.CRITICAL,
                description=f"Error checking bucket visibility: {str(e)}"
            ))
    
    def check_4_2_bucket_encryption(self):
        """CIS 4.2 - Ensure Object Storage buckets are encrypted with CMK"""
        import oci
        try:
            namespace = self.object_storage.get_namespace().data
            compartments = self.get_all_compartments()
            unencrypted_buckets = []
            
            for compartment in compartments:
                try:
                    buckets = oci.pagination.list_call_get_all_results(
                        self.object_storage.list_buckets,
                        namespace,
                        compartment.id
                    ).data
                    
                    for bucket in buckets:
                        bucket_details = self.object_storage.get_bucket(namespace, bucket.name).data
                        if not bucket_details.kms_key_id:
                            unencrypted_buckets.append({
                                "bucket": bucket.name,
                                "compartment": compartment.name
                            })
                except Exception:
                    continue
            
            if unencrypted_buckets:
                self.add_finding(Finding(
                    cis_control="4.2",
                    title="Bucket Encryption with CMK",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    description=f"{len(unencrypted_buckets)} buckets are not encrypted with a customer-managed key.",
                    details={"unencrypted_buckets": unencrypted_buckets[:10]},
                    recommendation="Enable encryption with customer-managed keys for all buckets."
                ))
            else:
                self.add_finding(Finding(
                    cis_control="4.2",
                    title="Bucket Encryption with CMK",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    description="All buckets are encrypted with customer-managed keys."
                ))
        except Exception as e:
            self.add_finding(Finding(
                cis_control="4.2",
                title="Bucket Encryption with CMK",
                status=Status.ERROR,
                severity=Severity.HIGH,
                description=f"Error checking bucket encryption: {str(e)}"
            ))
    
    def check_4_3_bucket_versioning(self):
        """CIS 4.3 - Ensure Object Storage bucket versioning is enabled"""
        import oci
        try:
            namespace = self.object_storage.get_namespace().data
            compartments = self.get_all_compartments()
            unversioned_buckets = []
            
            for compartment in compartments:
                try:
                    buckets = oci.pagination.list_call_get_all_results(
                        self.object_storage.list_buckets,
                        namespace,
                        compartment.id
                    ).data
                    
                    for bucket in buckets:
                        bucket_details = self.object_storage.get_bucket(namespace, bucket.name).data
                        if bucket_details.versioning != "Enabled":
                            unversioned_buckets.append({
                                "bucket": bucket.name,
                                "compartment": compartment.name,
                                "versioning": bucket_details.versioning
                            })
                except Exception:
                    continue
            
            if unversioned_buckets:
                self.add_finding(Finding(
                    cis_control="4.3",
                    title="Bucket Versioning",
                    status=Status.WARNING,
                    severity=Severity.MEDIUM,
                    description=f"{len(unversioned_buckets)} buckets do not have versioning enabled.",
                    details={"unversioned_buckets": unversioned_buckets[:10]},
                    recommendation="Enable versioning on critical buckets for data protection."
                ))
            else:
                self.add_finding(Finding(
                    cis_control="4.3",
                    title="Bucket Versioning",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    description="All buckets have versioning enabled."
                ))
        except Exception as e:
            self.add_finding(Finding(
                cis_control="4.3",
                title="Bucket Versioning",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                description=f"Error checking bucket versioning: {str(e)}"
            ))

    # ========================================================================
    # Section 5: Asset Management / Compute
    # ========================================================================
    
    def check_5_1_boot_volume_encryption(self):
        """CIS 5.1 - Ensure boot volumes are encrypted with CMK"""
        import oci
        try:
            compartments = self.get_all_compartments()
            unencrypted_volumes = []
            
            for compartment in compartments:
                try:
                    instances = oci.pagination.list_call_get_all_results(
                        self.compute.list_instances,
                        compartment.id
                    ).data
                    
                    for instance in instances:
                        if instance.lifecycle_state == "RUNNING":
                            boot_attachments = oci.pagination.list_call_get_all_results(
                                self.compute.list_boot_volume_attachments,
                                instance.availability_domain,
                                compartment.id,
                                instance_id=instance.id
                            ).data
                            
                            for attachment in boot_attachments:
                                try:
                                    block_client = oci.core.BlockstorageClient(self.config) if not self.signer else oci.core.BlockstorageClient(config={}, signer=self.signer)
                                    boot_volume = block_client.get_boot_volume(attachment.boot_volume_id).data
                                    if not boot_volume.kms_key_id:
                                        unencrypted_volumes.append({
                                            "instance": instance.display_name,
                                            "boot_volume": boot_volume.display_name,
                                            "compartment": compartment.name
                                        })
                                except Exception:
                                    pass
                except Exception:
                    continue
            
            if unencrypted_volumes:
                self.add_finding(Finding(
                    cis_control="5.1",
                    title="Boot Volume Encryption",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    description=f"{len(unencrypted_volumes)} boot volumes are not encrypted with CMK.",
                    details={"unencrypted_volumes": unencrypted_volumes[:10]},
                    recommendation="Enable encryption with customer-managed keys for boot volumes."
                ))
            else:
                self.add_finding(Finding(
                    cis_control="5.1",
                    title="Boot Volume Encryption",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    description="All boot volumes are encrypted with customer-managed keys."
                ))
        except Exception as e:
            self.add_finding(Finding(
                cis_control="5.1",
                title="Boot Volume Encryption",
                status=Status.ERROR,
                severity=Severity.HIGH,
                description=f"Error checking boot volume encryption: {str(e)}"
            ))
    
    def check_5_2_block_volume_encryption(self):
        """CIS 5.2 - Ensure block volumes are encrypted with CMK"""
        import oci
        try:
            compartments = self.get_all_compartments()
            unencrypted_volumes = []
            
            for compartment in compartments:
                try:
                    block_client = oci.core.BlockstorageClient(self.config) if not self.signer else oci.core.BlockstorageClient(config={}, signer=self.signer)
                    volumes = oci.pagination.list_call_get_all_results(
                        block_client.list_volumes,
                        compartment.id
                    ).data
                    
                    for volume in volumes:
                        if volume.lifecycle_state == "AVAILABLE":
                            if not volume.kms_key_id:
                                unencrypted_volumes.append({
                                    "volume": volume.display_name,
                                    "compartment": compartment.name
                                })
                except Exception:
                    continue
            
            if unencrypted_volumes:
                self.add_finding(Finding(
                    cis_control="5.2",
                    title="Block Volume Encryption",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    description=f"{len(unencrypted_volumes)} block volumes are not encrypted with CMK.",
                    details={"unencrypted_volumes": unencrypted_volumes[:10]},
                    recommendation="Enable encryption with customer-managed keys for block volumes."
                ))
            else:
                self.add_finding(Finding(
                    cis_control="5.2",
                    title="Block Volume Encryption",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    description="All block volumes are encrypted with customer-managed keys."
                ))
        except Exception as e:
            self.add_finding(Finding(
                cis_control="5.2",
                title="Block Volume Encryption",
                status=Status.ERROR,
                severity=Severity.HIGH,
                description=f"Error checking block volume encryption: {str(e)}"
            ))

    # ========================================================================
    # Run All Checks
    # ========================================================================
    
    def run_all_checks(self):
        """Run all CIS benchmark checks"""
        print("\n" + "="*70)
        print("OCI CIS Benchmark Scanner")
        print("="*70)
        print(f"Tenancy: {self.tenancy_id}")
        print(f"Scan started: {datetime.utcnow().isoformat()}")
        print("="*70)
        
        # Section 1: IAM
        print("\n[Section 1: Identity and Access Management]")
        self.check_1_1_service_level_admins()
        self.check_1_2_mfa_enabled()
        self.check_1_3_api_keys_rotation()
        self.check_1_4_auth_token_rotation()
        self.check_1_5_customer_secret_keys_rotation()
        self.check_1_6_password_policy()
        self.check_1_7_local_admin_users()
        
        # Section 2: Networking
        print("\n[Section 2: Networking]")
        self.check_2_1_default_security_list()
        self.check_2_2_ssh_restricted()
        self.check_2_3_rdp_restricted()
        self.check_2_4_nsg_unrestricted()
        
        # Section 3: Logging and Monitoring
        print("\n[Section 3: Logging and Monitoring]")
        self.check_3_1_audit_retention()
        self.check_3_2_default_tags()
        self.check_3_3_notifications_for_iam_changes()
        self.check_3_4_vcn_flow_logs()
        self.check_3_5_cloud_guard_enabled()
        
        # Section 4: Object Storage
        print("\n[Section 4: Object Storage]")
        self.check_4_1_public_buckets()
        self.check_4_2_bucket_encryption()
        self.check_4_3_bucket_versioning()
        
        # Section 5: Asset Management / Compute
        print("\n[Section 5: Asset Management / Compute]")
        self.check_5_1_boot_volume_encryption()
        self.check_5_2_block_volume_encryption()
        
        return self.findings
    
    def generate_report(self):
        """Generate a summary report of findings"""
        print("\n" + "="*70)
        print("SCAN SUMMARY")
        print("="*70)
        
        # Count by status
        pass_count = len([f for f in self.findings if f.status == Status.PASS])
        fail_count = len([f for f in self.findings if f.status == Status.FAIL])
        warning_count = len([f for f in self.findings if f.status == Status.WARNING])
        error_count = len([f for f in self.findings if f.status == Status.ERROR])
        
        print(f"\n✅ PASSED:   {pass_count}")
        print(f"❌ FAILED:   {fail_count}")
        print(f"⚠️  WARNING:  {warning_count}")
        print(f"🔴 ERROR:    {error_count}")
        
        # Count by severity for failures
        if fail_count > 0:
            print("\n--- Failed Checks by Severity ---")
            for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
                count = len([f for f in self.findings if f.status == Status.FAIL and f.severity == sev])
                if count > 0:
                    print(f"  {sev.value}: {count}")
        
        # List failed controls
        failed = [f for f in self.findings if f.status == Status.FAIL]
        if failed:
            print("\n--- Failed Controls ---")
            for f in failed:
                print(f"\n  [{f.cis_control}] {f.title}")
                print(f"    Severity: {f.severity.value}")
                print(f"    Issue: {f.description}")
                if f.recommendation:
                    print(f"    Recommendation: {f.recommendation}")
        
        return {
            "summary": {
                "passed": pass_count,
                "failed": fail_count,
                "warning": warning_count,
                "error": error_count,
                "total": len(self.findings)
            },
            "findings": [
                {
                    "cis_control": f.cis_control,
                    "title": f.title,
                    "status": f.status.value,
                    "severity": f.severity.value,
                    "description": f.description,
                    "recommendation": f.recommendation,
                    "details": f.details
                }
                for f in self.findings
            ]
        }


# ============================================================================
# Main Execution
# ============================================================================

def main():
    """Main function to run the CIS scanner"""
    import oci
    
    print("Loading OCI configuration...")
    
    try:
        # Try to load from default config file
        if OCI_CONFIG_FILE:
            config = oci.config.from_file(OCI_CONFIG_FILE, OCI_CONFIG_PROFILE)
        else:
            config = oci.config.from_file(profile_name=OCI_CONFIG_PROFILE)
        
        oci.config.validate_config(config)
        print(f"✅ Configuration loaded successfully")
        print(f"   Tenancy: {config.get('tenancy')}")
        print(f"   Region: {config.get('region')}")
        
        # Create scanner and run
        scanner = CISScanner(config)
        scanner.run_all_checks()
        report = scanner.generate_report()
        
        # Save report to file
        report_filename = f"oci_cis_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_filename, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n📄 Full report saved to: {report_filename}")
        
    except oci.exceptions.ConfigFileNotFound:
        print("❌ OCI config file not found!")
        print("   Please run 'oci setup config' to create your configuration.")
    except oci.exceptions.InvalidConfig as e:
        print(f"❌ Invalid OCI configuration: {e}")
        print("   Please check your ~/.oci/config file.")
    except Exception as e:
        print(f"❌ Error: {e}")
        raise


if __name__ == "__main__":
    main()