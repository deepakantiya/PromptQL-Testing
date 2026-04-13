import executor
"""
OCI CIS Scanner - PromptQL Integration
======================================
Run this after setting up the OCI custom integration.
"""
from executor import aio
import json

async def main():
    print("=" * 60)
    print("OCI CIS Benchmark Scanner")
    print("=" * 60)
    
    # Call the OCI CIS Scanner function via custom integration
    print("\n[1] Calling OCI CIS Scanner function...")
    
    response = await aio.run_http(
        url="/v1/scan",
        method="POST",
        headers={"Content-Type": "application/json"},
        body={},
        integration="oci_cis_scanner",
        description="Running CIS benchmark compliance scan against OCI tenancy"
    )
    
    if response.get("status") != 200:
        print(f"❌ Error calling scanner: {response}")
        return
    
    result = response.get("body", {})
    
    # Parse results
    summary = result.get("summary", {})
    findings = result.get("findings", [])
    
    print(f"\n[2] Scan Complete!")
    print(f"    Timestamp: {summary.get('scan_timestamp')}")
    print(f"    Region: {summary.get('region')}")
    print(f"    Compartments Scanned: {summary.get('compartments_scanned')}")
    print(f"\n[3] Summary:")
    print(f"    ✅ Passed: {summary.get('passed', 0)}")
    print(f"    ❌ Failed: {summary.get('failed', 0)}")
    print(f"    ⚠️  Errors: {summary.get('errors', 0)}")
    
    # Format findings for artifact
    formatted_findings = []
    for f in findings:
        formatted_findings.append({
            "CIS Control": f.get("check_id", ""),
            "Status": f.get("status", ""),
            "Resource": f.get("resource", ""),
            "Finding": f.get("detail", "")
        })
    
    # Separate passed and failed
    failed_findings = [f for f in formatted_findings if f["Status"] == "FAIL"]
    passed_findings = [f for f in formatted_findings if f["Status"] == "PASS"]
    error_findings = [f for f in formatted_findings if f["Status"] == "ERROR"]
    
    # Store artifacts
    if failed_findings:
        print(f"\n[4] Critical Findings ({len(failed_findings)}):")
        for f in failed_findings[:5]:
            print(f"    ❌ {f['CIS Control']}: {f['Finding'][:60]}...")
        
        await aio.store_artifact(
            identifier='cis_failed_checks',
            title='CIS Benchmark - Failed Checks',
            artifact_type='table',
            data=failed_findings
        )
    
    if passed_findings:
        await aio.store_artifact(
            identifier='cis_passed_checks',
            title='CIS Benchmark - Passed Checks',
            artifact_type='table',
            data=passed_findings
        )
    
    # Store full report
    await aio.store_artifact(
        identifier='cis_full_report',
        title='CIS Benchmark - Full Report',
        artifact_type='text',
        data=json.dumps(result, indent=2),
        metadata={'text': {'content_type': 'application/json'}}
    )
    
    # Summary artifact
    summary_data = [{
        "Metric": "Scan Timestamp",
        "Value": summary.get('scan_timestamp', 'N/A')
    }, {
        "Metric": "Region",
        "Value": summary.get('region', 'N/A')
    }, {
        "Metric": "Compartments Scanned",
        "Value": str(summary.get('compartments_scanned', 0))
    }, {
        "Metric": "Total Checks",
        "Value": str(summary.get('total_checks', 0))
    }, {
        "Metric": "Passed",
        "Value": str(summary.get('passed', 0))
    }, {
        "Metric": "Failed",
        "Value": str(summary.get('failed', 0))
    }, {
        "Metric": "Errors",
        "Value": str(summary.get('errors', 0))
    }, {
        "Metric": "Compliance Rate",
        "Value": f"{round(100 * summary.get('passed', 0) / max(summary.get('total_checks', 1), 1), 1)}%"
    }]
    
    await aio.store_artifact(
        identifier='cis_summary',
        title='CIS Benchmark - Summary',
        artifact_type='table',
        data=summary_data
    )
    
    print("\n" + "=" * 60)
    print("Scan artifacts created successfully!")
    print("=" * 60)