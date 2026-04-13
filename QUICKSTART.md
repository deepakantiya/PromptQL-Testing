# Quick Start - OCI CIS Scanner Deployment
## Your Configuration: `us-sanjose-1`

### Prerequisites Checklist
- [ ] OCI CLI installed and configured (`oci setup config`)
- [ ] Terraform installed (`brew install terraform`)
- [ ] Docker installed and running
- [ ] Fn CLI installed (`brew install fn`)
- [ ] OCI API Key configured in `~/.oci/config`

---

## Step 1: Complete Configuration

Edit `oci_function_terraform/terraform.tfvars` and fill in your OCI credentials:

```bash
# Navigate to the terraform directory
cd oci_function_terraform

# Edit the tfvars file
# nano terraform.tfvars  (or your preferred editor)
```

Find these values in the OCI Console:

| Variable | Where to Find |
|----------|---------------|
| `tenancy_ocid` | Administration → Tenancy Details → OCID |
| `user_ocid` | Identity → Users → [Your User] → OCID |
| `fingerprint` | Identity → Users → [Your User] → API Keys |
| `private_key_path` | Path to your OCI API private key (usually `~/.oci/oci_api_key.pem`) |

---

## Step 2: Deploy Infrastructure

```bash
cd oci_function_terraform
terraform init
terraform apply
```

Note the outputs:
- `api_gateway_endpoint` - The URL to call
- `api_key` - Your authentication key
- `namespace` - Your OCI namespace

---

## Step 3: Deploy the Function

```bash
cd ../oci_function

# Login to OCI Container Registry
# Use your OCI username and Auth Token as password
docker login us-sanjose-1.ocir.io

# Build the function
fn build

# Tag and push to registry
docker tag cis-benchmark-scanner:0.0.1 us-sanjose-1.ocir.io/<namespace>/cis-benchmark-scanner:0.0.1
docker push us-sanjose-1.ocir.io/<namespace>/cis-benchmark-scanner:0.0.1

# Deploy using Fn CLI
fn create context oci-cis --provider oracle
fn use context oci-cis
fn update context oracle.compartment-id <your-compartment-ocid>
fn update context api-url https://functions.us-sanjose-1.oci.oraclecloud.com
fn update context registry us-sanjose-1.ocir.io/<namespace>
fn deploy --app cis-benchmark-scanner --no-bump
```

---

## Step 4: Test the Scanner

```bash
curl -X POST "https://<gateway-endpoint>/v1/scan" \
  -H "x-api-key: <your-api-key>" \
  -H "Content-Type: application/json"
```

---

## Step 5: Connect to PromptQL

1. Go to **PromptQL → My Data → Add Custom Integration**
2. Configure:

| Setting | Value |
|---------|-------|
| Name | OCI CIS Scanner |
| Provider ID | oci_cis_scanner |
| Base URL | https://<gateway-hostname> |
| Authentication | API Key |
| API Key Header | `x-api-key` |
| API Key | *(from terraform output)* |
| Notes | POST to /v1/scan to run CIS benchmark compliance scan |

3. **Click Connect**

---

## Step 5: Run from PromptQL! 🎉

Just ask:
> "Run the OCI CIS benchmark scan and show me the results"

Or:
> "Check my OCI tenancy for security misconfigurations"

---

## Troubleshooting

### "Could not get resource principal signer"
The function is running outside OCI or the dynamic group/policy isn't configured correctly.

```bash
# Verify dynamic group
oci iam dynamic-group list --compartment-id <tenancy-ocid> | grep cis-scanner

# Verify policy
oci iam policy list --compartment-id <tenancy-ocid> | grep cis-scanner
```

### Function timeout
Increase the timeout in `func.yaml` (currently 300 seconds).

### API Gateway 401/403
- Verify the x-api-key header matches
- Check API Gateway deployment is ACTIVE

### Docker login fails
Generate a new Auth Token at: OCI Console → Your User → Auth Tokens
