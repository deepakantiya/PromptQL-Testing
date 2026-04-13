import executor
"""
OCI Compute Handler Function
Handles compute-related API calls (instances, volumes)
"""
import io
import json
import logging
from fdk import response
import oci

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_signer():
    return oci.auth.signers.get_resource_principals_signer()

def validate_api_key(ctx):
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
    headers = ctx.Headers() if hasattr(ctx, 'Headers') else {}
    for name, value in headers.items():
        if name.lower() == "x-operation":
            return value[0] if isinstance(value, list) else value
    return None

def get_all_compartments(identity_client, tenancy_id):
    compartments = [{"id": tenancy_id, "name": "root"}]
    for c in oci.pagination.list_call_get_all_results(
        identity_client.list_compartments,
        compartment_id=tenancy_id,
        compartment_id_in_subtree=True,
        lifecycle_state="ACTIVE"
    ).data:
        compartments.append({"id": c.id, "name": c.name})
    return compartments

def list_instances(compute_client, identity_client, tenancy_id):
    compartments = get_all_compartments(identity_client, tenancy_id)
    instances = []
    
    for comp in compartments:
        try:
            for instance in oci.pagination.list_call_get_all_results(
                compute_client.list_instances,
                compartment_id=comp["id"]
            ).data:
                if instance.lifecycle_state == "TERMINATED":
                    continue
                    
                instances.append({
                    "id": instance.id,
                    "display_name": instance.display_name,
                    "compartment_id": instance.compartment_id,
                    "compartment_name": comp["name"],
                    "availability_domain": instance.availability_domain,
                    "shape": instance.shape,
                    "lifecycle_state": instance.lifecycle_state,
                    "time_created": instance.time_created.isoformat() if instance.time_created else None
                })
        except Exception as e:
            logger.warning(f"Error listing instances in {comp['name']}: {e}")
    
    return instances

def list_volumes(block_storage_client, identity_client, tenancy_id):
    compartments = get_all_compartments(identity_client, tenancy_id)
    volumes = []
    
    for comp in compartments:
        try:
            # Block volumes
            for vol in oci.pagination.list_call_get_all_results(
                block_storage_client.list_volumes,
                compartment_id=comp["id"]
            ).data:
                if vol.lifecycle_state == "TERMINATED":
                    continue
                
                has_cmk = vol.kms_key_id is not None
                volumes.append({
                    "id": vol.id,
                    "display_name": vol.display_name,
                    "type": "block_volume",
                    "compartment_id": vol.compartment_id,
                    "compartment_name": comp["name"],
                    "availability_domain": vol.availability_domain,
                    "size_in_gbs": vol.size_in_gbs,
                    "kms_key_id": vol.kms_key_id,
                    "has_cmk_encryption": has_cmk,
                    "is_hydrated": vol.is_hydrated,
                    "lifecycle_state": vol.lifecycle_state,
                    "time_created": vol.time_created.isoformat() if vol.time_created else None,
                    "cis_4_2_1_compliant": has_cmk
                })
            
            # Boot volumes
            for boot_vol in oci.pagination.list_call_get_all_results(
                block_storage_client.list_boot_volumes,
                compartment_id=comp["id"]
            ).data:
                if boot_vol.lifecycle_state == "TERMINATED":
                    continue
                
                has_cmk = boot_vol.kms_key_id is not None
                volumes.append({
                    "id": boot_vol.id,
                    "display_name": boot_vol.display_name,
                    "type": "boot_volume",
                    "compartment_id": boot_vol.compartment_id,
                    "compartment_name": comp["name"],
                    "availability_domain": boot_vol.availability_domain,
                    "size_in_gbs": boot_vol.size_in_gbs,
                    "kms_key_id": boot_vol.kms_key_id,
                    "has_cmk_encryption": has_cmk,
                    "lifecycle_state": boot_vol.lifecycle_state,
                    "time_created": boot_vol.time_created.isoformat() if boot_vol.time_created else None,
                    "cis_4_2_2_compliant": has_cmk
                })
        except Exception as e:
            logger.warning(f"Error listing volumes in {comp['name']}: {e}")
    
    return volumes

def handler(ctx, data: io.BytesIO = None):
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
        compute_client = oci.core.ComputeClient(config={}, signer=signer)
        block_storage_client = oci.core.BlockstorageClient(config={}, signer=signer)
        
        result = None
        
        if operation == "list_instances":
            result = list_instances(compute_client, identity_client, tenancy_id)
        elif operation == "list_volumes":
            result = list_volumes(block_storage_client, identity_client, tenancy_id)
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