import executor
"""
OCI Security Handler Function
Handles Cloud Guard, KMS, and security-related API calls
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

def get_cloud_guard_status(cloud_guard_client, tenancy_id):
    """Get Cloud Guard configuration status"""
    try:
        config = cloud_guard_client.get_configuration(compartment_id=tenancy_id).data
        
        # Get targets
        targets = []
        try:
            for target in oci.pagination.list_call_get_all_results(
                cloud_guard_client.list_targets,
                compartment_id=tenancy_id
            ).data:
                targets.append({
                    "id": target.id,
                    "display_name": target.display_name,
                    "target_resource_type": target.target_resource_type,
                    "lifecycle_state": target.lifecycle_state
                })
        except Exception as e:
            logger.warning(f"Could not list targets: {e}")
        
        return {
            "status": config.status,
            "reporting_region": config.reporting_region,
            "is_enabled": config.status == "ENABLED",
            "targets": targets,
            "target_count": len(targets),
            "cis_3_5_compliant": config.status == "ENABLED"
        }
    except oci.exceptions.ServiceError as e:
        if e.status == 404:
            return {
                "status": "NOT_ENABLED",
                "is_enabled": False,
                "targets": [],
                "target_count": 0,
                "cis_3_5_compliant": False,
                "message": "Cloud Guard is not enabled for this tenancy"
            }
        raise

def list_cloud_guard_problems(cloud_guard_client, tenancy_id):
    """List Cloud Guard detected problems"""
    problems = []
    
    try:
        for problem in oci.pagination.list_call_get_all_results(
            cloud_guard_client.list_problems,
            compartment_id=tenancy_id,
            lifecycle_state="ACTIVE"
        ).data:
            problems.append({
                "id": problem.id,
                "compartment_id": problem.compartment_id,
                "resource_id": problem.resource_id,
                "resource_name": problem.resource_name,
                "resource_type": problem.resource_type,
                "detector_id": problem.detector_id,
                "detector_rule_id": problem.detector_rule_id,
                "risk_level": problem.risk_level,
                "lifecycle_state": problem.lifecycle_state,
                "labels": problem.labels,
                "time_first_detected": problem.time_first_detected.isoformat() if problem.time_first_detected else None,
                "time_last_detected": problem.time_last_detected.isoformat() if problem.time_last_detected else None
            })
    except oci.exceptions.ServiceError as e:
        if e.status == 404:
            return {
                "problems": [],
                "message": "Cloud Guard not enabled or no access"
            }
        raise
    
    # Summary by risk level
    summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "MINOR": 0
    }
    for p in problems:
        if p["risk_level"] in summary:
            summary[p["risk_level"]] += 1
    
    return {
        "problems": problems,
        "total_count": len(problems),
        "summary_by_risk": summary
    }

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
        
        cloud_guard_client = oci.cloud_guard.CloudGuardClient(config={}, signer=signer)
        
        result = None
        
        if operation == "cloud_guard_status":
            result = get_cloud_guard_status(cloud_guard_client, tenancy_id)
        elif operation == "list_problems":
            result = list_cloud_guard_problems(cloud_guard_client, tenancy_id)
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