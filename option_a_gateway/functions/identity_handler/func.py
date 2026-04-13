import executor
"""
OCI Identity Handler Function
Handles all identity-related API calls
"""
import io
import json
import logging
import os
from fdk import response
import oci

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_signer():
    """Get Resource Principal signer"""
    return oci.auth.signers.get_resource_principals_signer()

def validate_api_key(ctx):
    """Validate API key from request headers"""
    headers = ctx.Headers() if hasattr(ctx, 'Headers') else {}
    
    api_key = None
    expected_key = None
    
    for name, value in headers.items():
        val = value[0] if isinstance(value, list) else value
        if name.lower() == "x-api-key":
            api_key = val
        if name.lower() == "x-expected-api-key":
            expected_key = val
    
    if expected_key and api_key != expected_key:
        return False
    return True

def get_operation(ctx):
    """Get operation type from headers"""
    headers = ctx.Headers() if hasattr(ctx, 'Headers') else {}
    for name, value in headers.items():
        if name.lower() == "x-operation":
            return value[0] if isinstance(value, list) else value
    return None

def list_users(identity_client, tenancy_id):
    """List all users with MFA and API key info"""
    users = []
    for user in oci.pagination.list_call_get_all_results(
        identity_client.list_users,
        compartment_id=tenancy_id
    ).data:
        # Get MFA status
        mfa_devices = identity_client.list_mfa_totp_devices(user_id=user.id).data
        mfa_enabled = any(d.is_activated for d in mfa_devices)
        
        # Get API keys
        api_keys = identity_client.list_api_keys(user_id=user.id).data
        
        users.append({
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "lifecycle_state": user.lifecycle_state,
            "is_mfa_activated": mfa_enabled,
            "mfa_device_count": len(mfa_devices),
            "api_key_count": len(api_keys),
            "api_keys": [
                {
                    "fingerprint": k.fingerprint,
                    "time_created": k.time_created.isoformat() if k.time_created else None,
                    "lifecycle_state": k.lifecycle_state
                }
                for k in api_keys
            ],
            "time_created": user.time_created.isoformat() if user.time_created else None,
            "last_successful_login": user.last_successful_login_time.isoformat() if user.last_successful_login_time else None
        })
    return users

def list_groups(identity_client, tenancy_id):
    """List all groups with member counts"""
    groups = []
    for group in oci.pagination.list_call_get_all_results(
        identity_client.list_groups,
        compartment_id=tenancy_id
    ).data:
        # Get members
        memberships = identity_client.list_user_group_memberships(
            compartment_id=tenancy_id,
            group_id=group.id
        ).data
        
        groups.append({
            "id": group.id,
            "name": group.name,
            "description": group.description,
            "lifecycle_state": group.lifecycle_state,
            "member_count": len(memberships),
            "time_created": group.time_created.isoformat() if group.time_created else None
        })
    return groups

def list_policies(identity_client, tenancy_id):
    """List all policies"""
    policies = []
    
    # Get all compartments
    compartments = oci.pagination.list_call_get_all_results(
        identity_client.list_compartments,
        compartment_id=tenancy_id,
        compartment_id_in_subtree=True
    ).data
    
    # Include root compartment
    compartment_ids = [tenancy_id] + [c.id for c in compartments]
    
    for comp_id in compartment_ids:
        try:
            for policy in oci.pagination.list_call_get_all_results(
                identity_client.list_policies,
                compartment_id=comp_id
            ).data:
                policies.append({
                    "id": policy.id,
                    "name": policy.name,
                    "compartment_id": policy.compartment_id,
                    "statements": policy.statements,
                    "lifecycle_state": policy.lifecycle_state,
                    "time_created": policy.time_created.isoformat() if policy.time_created else None
                })
        except Exception as e:
            logger.warning(f"Could not list policies in {comp_id}: {e}")
    
    return policies

def list_compartments(identity_client, tenancy_id):
    """List all compartments"""
    compartments = [{
        "id": tenancy_id,
        "name": "root",
        "description": "Root compartment (tenancy)",
        "lifecycle_state": "ACTIVE",
        "parent_compartment_id": None
    }]
    
    for comp in oci.pagination.list_call_get_all_results(
        identity_client.list_compartments,
        compartment_id=tenancy_id,
        compartment_id_in_subtree=True,
        lifecycle_state="ACTIVE"
    ).data:
        compartments.append({
            "id": comp.id,
            "name": comp.name,
            "description": comp.description,
            "lifecycle_state": comp.lifecycle_state,
            "parent_compartment_id": comp.compartment_id,
            "time_created": comp.time_created.isoformat() if comp.time_created else None
        })
    
    return compartments

def get_authentication_policy(identity_client, tenancy_id):
    """Get tenancy authentication policy"""
    policy = identity_client.get_authentication_policy(compartment_id=tenancy_id).data
    
    return {
        "compartment_id": policy.compartment_id,
        "password_policy": {
            "minimum_password_length": policy.password_policy.minimum_password_length,
            "is_lowercase_characters_required": policy.password_policy.is_lowercase_characters_required,
            "is_uppercase_characters_required": policy.password_policy.is_uppercase_characters_required,
            "is_numeric_characters_required": policy.password_policy.is_numeric_characters_required,
            "is_special_characters_required": policy.password_policy.is_special_characters_required,
            "is_username_containment_allowed": policy.password_policy.is_username_containment_allowed
        },
        "network_policy": {
            "network_source_ids": policy.network_policy.network_source_ids if policy.network_policy else []
        }
    }

def handler(ctx, data: io.BytesIO = None):
    """Main handler"""
    try:
        if not validate_api_key(ctx):
            return response.Response(
                ctx,
                response_data=json.dumps({"error": "Unauthorized"}),
                headers={"Content-Type": "application/json"},
                status_code=401
            )
        
        operation = get_operation(ctx)
        signer = get_signer()
        tenancy_id = signer.tenancy_id
        identity_client = oci.identity.IdentityClient(config={}, signer=signer)
        
        result = None
        
        if operation == "list_users":
            result = list_users(identity_client, tenancy_id)
        elif operation == "list_groups":
            result = list_groups(identity_client, tenancy_id)
        elif operation == "list_policies":
            result = list_policies(identity_client, tenancy_id)
        elif operation == "list_compartments":
            result = list_compartments(identity_client, tenancy_id)
        elif operation == "get_auth_policy":
            result = get_authentication_policy(identity_client, tenancy_id)
        else:
            return response.Response(
                ctx,
                response_data=json.dumps({"error": f"Unknown operation: {operation}"}),
                headers={"Content-Type": "application/json"},
                status_code=400
            )
        
        return response.Response(
            ctx,
            response_data=json.dumps({"data": result, "operation": operation}),
            headers={"Content-Type": "application/json"}
        )
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return response.Response(
            ctx,
            response_data=json.dumps({"error": str(e)}),
            headers={"Content-Type": "application/json"},
            status_code=500
        )