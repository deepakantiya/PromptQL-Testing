import executor
"""
OCI Storage Handler Function
Handles storage-related API calls (Object Storage, Block Volumes)
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

def list_buckets(object_storage_client, identity_client, tenancy_id, namespace):
    compartments = get_all_compartments(identity_client, tenancy_id)
    buckets = []
    
    for comp in compartments:
        try:
            for bucket_summary in oci.pagination.list_call_get_all_results(
                object_storage_client.list_buckets,
                namespace_name=namespace,
                compartment_id=comp["id"]
            ).data:
                # Get full bucket details
                bucket = object_storage_client.get_bucket(
                    namespace_name=namespace,
                    bucket_name=bucket_summary.name
                ).data
                
                # Check for CIS violations
                is_public = bucket.public_access_type != "NoPublicAccess"
                has_cmk = bucket.kms_key_id is not None
                versioning_enabled = bucket.versioning == "Enabled"
                
                buckets.append({
                    "name": bucket.name,
                    "namespace": namespace,
                    "compartment_id": bucket.compartment_id,
                    "compartment_name": comp["name"],
                    "public_access_type": bucket.public_access_type,
                    "is_public": is_public,
                    "storage_tier": bucket.storage_tier,
                    "kms_key_id": bucket.kms_key_id,
                    "has_cmk_encryption": has_cmk,
                    "versioning": bucket.versioning,
                    "versioning_enabled": versioning_enabled,
                    "object_lifecycle_policy_etag": bucket.object_lifecycle_policy_etag,
                    "replication_enabled": bucket.replication_enabled,
                    "time_created": bucket.time_created.isoformat() if bucket.time_created else None,
                    # CIS compliance flags
                    "cis_4_1_1_compliant": not is_public,
                    "cis_4_1_2_compliant": has_cmk,
                    "cis_4_1_3_compliant": versioning_enabled
                })
        except Exception as e:
            logger.warning(f"Error listing buckets in {comp['name']}: {e}")
    
    return buckets

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
        object_storage_client = oci.object_storage.ObjectStorageClient(config={}, signer=signer)
        
        namespace = object_storage_client.get_namespace().data
        
        result = None
        
        if operation == "list_buckets":
            result = list_buckets(object_storage_client, identity_client, tenancy_id, namespace)
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