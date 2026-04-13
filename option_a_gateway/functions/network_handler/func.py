import executor
"""
OCI Network Handler Function
Handles all network-related API calls
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

def list_vcns(network_client, compartments):
    vcns = []
    for comp in compartments:
        try:
            for vcn in oci.pagination.list_call_get_all_results(
                network_client.list_vcns,
                compartment_id=comp["id"]
            ).data:
                vcns.append({
                    "id": vcn.id,
                    "display_name": vcn.display_name,
                    "compartment_id": vcn.compartment_id,
                    "compartment_name": comp["name"],
                    "cidr_blocks": vcn.cidr_blocks,
                    "dns_label": vcn.dns_label,
                    "lifecycle_state": vcn.lifecycle_state,
                    "time_created": vcn.time_created.isoformat() if vcn.time_created else None
                })
        except Exception as e:
            logger.warning(f"Error listing VCNs in {comp['name']}: {e}")
    return vcns

def list_security_lists(network_client, compartments):
    security_lists = []
    for comp in compartments:
        try:
            for sl in oci.pagination.list_call_get_all_results(
                network_client.list_security_lists,
                compartment_id=comp["id"]
            ).data:
                # Analyze ingress rules for CIS violations
                risky_ingress = []
                for rule in sl.ingress_security_rules or []:
                    source = rule.source
                    if source == "0.0.0.0/0":
                        protocol = rule.protocol
                        tcp_opts = rule.tcp_options
                        
                        port_info = "all ports"
                        if tcp_opts:
                            if tcp_opts.destination_port_range:
                                port_min = tcp_opts.destination_port_range.min
                                port_max = tcp_opts.destination_port_range.max
                                port_info = f"{port_min}-{port_max}" if port_min != port_max else str(port_min)
                        
                        risky_ingress.append({
                            "source": source,
                            "protocol": protocol,
                            "ports": port_info,
                            "is_ssh": tcp_opts and tcp_opts.destination_port_range and tcp_opts.destination_port_range.min <= 22 <= tcp_opts.destination_port_range.max if tcp_opts and tcp_opts.destination_port_range else False,
                            "is_rdp": tcp_opts and tcp_opts.destination_port_range and tcp_opts.destination_port_range.min <= 3389 <= tcp_opts.destination_port_range.max if tcp_opts and tcp_opts.destination_port_range else False
                        })
                
                security_lists.append({
                    "id": sl.id,
                    "display_name": sl.display_name,
                    "compartment_id": sl.compartment_id,
                    "compartment_name": comp["name"],
                    "vcn_id": sl.vcn_id,
                    "lifecycle_state": sl.lifecycle_state,
                    "ingress_rule_count": len(sl.ingress_security_rules or []),
                    "egress_rule_count": len(sl.egress_security_rules or []),
                    "risky_ingress_rules": risky_ingress,
                    "has_unrestricted_ingress": len(risky_ingress) > 0,
                    "has_ssh_from_internet": any(r["is_ssh"] for r in risky_ingress),
                    "has_rdp_from_internet": any(r["is_rdp"] for r in risky_ingress),
                    "time_created": sl.time_created.isoformat() if sl.time_created else None
                })
        except Exception as e:
            logger.warning(f"Error listing security lists in {comp['name']}: {e}")
    return security_lists

def list_nsgs(network_client, compartments):
    nsgs = []
    for comp in compartments:
        try:
            for nsg in oci.pagination.list_call_get_all_results(
                network_client.list_network_security_groups,
                compartment_id=comp["id"]
            ).data:
                # Get NSG rules
                rules = network_client.list_network_security_group_security_rules(
                    network_security_group_id=nsg.id
                ).data
                
                risky_rules = []
                for rule in rules:
                    if rule.direction == "INGRESS" and rule.source == "0.0.0.0/0":
                        tcp_opts = rule.tcp_options
                        port_info = "all ports"
                        if tcp_opts and tcp_opts.destination_port_range:
                            port_min = tcp_opts.destination_port_range.min
                            port_max = tcp_opts.destination_port_range.max
                            port_info = f"{port_min}-{port_max}" if port_min != port_max else str(port_min)
                        
                        risky_rules.append({
                            "source": rule.source,
                            "protocol": rule.protocol,
                            "ports": port_info
                        })
                
                nsgs.append({
                    "id": nsg.id,
                    "display_name": nsg.display_name,
                    "compartment_id": nsg.compartment_id,
                    "compartment_name": comp["name"],
                    "vcn_id": nsg.vcn_id,
                    "lifecycle_state": nsg.lifecycle_state,
                    "rule_count": len(rules),
                    "risky_ingress_rules": risky_rules,
                    "has_unrestricted_ingress": len(risky_rules) > 0,
                    "time_created": nsg.time_created.isoformat() if nsg.time_created else None
                })
        except Exception as e:
            logger.warning(f"Error listing NSGs in {comp['name']}: {e}")
    return nsgs

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
        network_client = oci.core.VirtualNetworkClient(config={}, signer=signer)
        
        compartments = get_all_compartments(identity_client, tenancy_id)
        
        result = None
        
        if operation == "list_vcns":
            result = list_vcns(network_client, compartments)
        elif operation == "list_security_lists":
            result = list_security_lists(network_client, compartments)
        elif operation == "list_nsgs":
            result = list_nsgs(network_client, compartments)
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