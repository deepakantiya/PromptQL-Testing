# OCI CIS Benchmark Scanner - Deployment Guide

This guide walks you through deploying the CIS Benchmark Scanner as an OCI Function and connecting it to PromptQL.

## Architecture

```
┌─────────────┐     HTTPS + API Key      ┌─────────────────┐
│  PromptQL   │ ───────────────────────► │  API Gateway    │
└─────────────┘                          └────────┬────────┘
                                                  │
                                                  ▼
                                         ┌─────────────────┐
                                         │  OCI Function   │
                                         │  (CIS Scanner)  │
                                         └────────┬────────┘
                                                  │
                                         Resource Principal
                                                  │
                    ┌─────────────────────────────┼─────────────────────────────┐
                    ▼                             ▼                             ▼
           ┌───────────────┐           ┌───────────────┐           ┌───────────────┐
           │    Identity   │           │   Networking  │           │    Storage    │
           │   (IAM, MFA)  │           │  (VCN, NSGs)  │           │   (Buckets)   │
           └───────────────┘           └───────────────┘           └───────────────┘
```

## Prerequisites

Before starting, ensure you have:

1. **OCI CLI** - Configured with API key authentication
   ```bash
   oci setup config
   ```

2. **Terraform** >= 1.0
   ```bash
   brew install terraform  # macOS
   ```

3. **Docker** - Running locally
   ```bash
   docker --version
   ```

4. **Fn CLI** - Oracle Functions CLI
   ```bash
   brew install fn
   ```

5. **OCI Permissions** - Your user needs:
   - `manage functions-family` in compartment
   - `manage api-gateway-family` in compartment
   - `manage virtual-network-family` in compartment
   - `manage repos` in tenancy (for container registry)

## Step 1: Configure Variables

Copy the template and fill in your values:

```bash
cd oci_function_terraform
cp terraform.tfvars.template terraform.tfvars
```

Edit `terraform.tfvars`:
```hcl
region           = "us-sanjose-1"
compartment_ocid = "ocid1.compartment.oc1..xxx"
tenancy_ocid     = "ocid1.tenancy.oc1..xxx"
user_ocid        = "ocid1.user.oc1..xxx"
fingerprint      = "aa:bb:cc:..."
private_key_path = "~/.oci/oci_api_key.pem"
```

## Step 2: Deploy Infrastructure

```bash
terraform init
terraform plan
terraform apply
```

This creates:
- VCN with public subnet
- API Gateway
- Function Application
- Dynamic Group and IAM Policies
- Container Registry

**Save the outputs:**
```
api_gateway_endpoint = "https://xxx.apigateway.us-sanjose-1.oci.customer-oci.com/v1/scan"
api_key = "abc123..."
namespace = "your-namespace"
```

## Step 3: Build and Push Function

```bash
cd ../oci_function

# Login to OCI Registry
docker login us-sanjose-1.ocir.io
# Username: <namespace>/<your-oci-username>
# Password: <auth-token>  (generate at: User Settings > Auth Tokens)

# Build function
fn build

# Tag for registry
docker tag cis-benchmark-scanner:0.0.1 \
  us-sanjose-1.ocir.io/<namespace>/cis-benchmark-scanner:0.0.1

# Push to registry
docker push us-sanjose-1.ocir.io/<namespace>/cis-benchmark-scanner:0.0.1
```

## Step 4: Deploy Function

```bash
# Configure Fn CLI
fn create context oci-cis --provider oracle
fn use context oci-cis
fn update context oracle.compartment-id <compartment-ocid>
fn update context api-url https://functions.us-sanjose-1.oci.oraclecloud.com
fn update context registry us-sanjose-1.ocir.io/<namespace>

# Deploy
fn deploy --app cis-benchmark-scanner --no-bump
```

## Step 5: Test the Function

```bash
curl -X POST "https://<gateway-endpoint>/v1/scan" \
  -H "x-api-key: <api-key>" \
  -H "Content-Type: application/json"
```

Expected response:
```json
{
  "scan_time": "2024-01-15T10:30:00Z",
  "tenancy": "ocid1.tenancy...",
  "summary": {
    "total_checks": 20,
    "passed": 15,
    "failed": 5
  },
  "findings": [...]
}
```

## Step 6: Connect to PromptQL

1. Go to **My Data** > **Add Custom Integration**
2. Fill in:
   - **Name**: OCI CIS Scanner
   - **Provider ID**: oci_cis_scanner
   - **Base URL**: `https://<gateway-hostname>`
   - **Auth Type**: API Key
   - **API Key Header**: `x-api-key`
   - **API Key**: *(from terraform output)*

3. Click **Connect**

## Troubleshooting

### Function not responding

Check function logs:
```bash
fn logs cis-benchmark-scanner cis-benchmark-scanner
```

### Permission Denied Errors

Verify the dynamic group and policies are correctly applied:
```bash
oci iam dynamic-group get --dynamic-group-id YOUR_DG_OCID
oci iam policy get --policy-id YOUR_POLICY_OCID
```

### API Gateway 401 Errors

- Verify the x-api-key header is included in requests
- Check the API key matches what's configured in the gateway

## Security Considerations

1. **Least Privilege**: The function has read-only access - it cannot modify resources
2. **API Key Rotation**: Rotate the API Gateway key periodically
3. **Network Isolation**: The function runs in a private subnet with internet access only for OCI API calls
4. **Audit Logging**: All API Gateway calls are logged in OCI Audit

## Estimated Costs

- **Functions**: ~$0.20 per million invocations
- **API Gateway**: ~$3/month per million API calls
- **VCN/Networking**: Minimal (data transfer only)

For daily scans, expect < $1/month total.
