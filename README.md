# OCI CIS Benchmark Scanner & Remediation

This package contains tools to scan your Oracle Cloud Infrastructure (OCI) tenancy against CIS benchmarks and remediate any misconfigurations using Infrastructure as Code (Terraform).

## Contents

| File | Description |
|------|-------------|
| `oci_cis_scanner.py` | Python script to scan OCI for CIS benchmark compliance |
| `oci_cis_remediation.tf` | Terraform configuration to remediate findings |
| `terraform.tfvars.template` | Template for Terraform variables |

## Quick Start

### 1. Prerequisites

```bash
# Install OCI CLI and Python SDK
pip install oci oci-cli

# Configure OCI CLI (creates ~/.oci/config)
oci setup config

# Install Terraform
# Download from: https://www.terraform.io/downloads
```

### 2. Run the Scanner

```bash
# Run the CIS benchmark scanner
python oci_cis_scanner.py

# Review the generated report
cat oci_cis_report_*.json
```

### 3. Apply Remediation

```bash
# Copy and configure variables
cp terraform.tfvars.template terraform.tfvars
# Edit terraform.tfvars with your values

# Initialize and apply
terraform init
terraform plan
terraform apply
```

## CIS Benchmark Controls

| Section | Controls |
|---------|----------|
| **1. IAM** | Password policy, MFA, API key rotation, admin groups |
| **2. Networking** | Security lists, NSGs, unrestricted ingress |
| **3. Logging** | Audit retention, Cloud Guard, VCN flow logs |
| **4. Storage** | Public buckets, encryption, versioning |
| **5. Compute** | Boot/block volume encryption |

## PromptQL Integration

Two deployment options are available for integrating with PromptQL:

### Option A: API Gateway Proxy (Recommended)
Located in `option_a_gateway/` - Provides real-time access to OCI APIs with 13+ endpoints.

### Option B: Single Function Scanner
Located in `oci_function/` - Runs complete CIS benchmark scans on demand.

See `DEPLOYMENT_GUIDE.md` for detailed instructions.

## CI/CD Integration

Example GitHub Actions workflow for automated scanning:

```yaml
name: OCI CIS Scan
on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install oci
      - name: Run CIS Scanner
        env:
          OCI_CLI_TENANCY: ${{ secrets.OCI_TENANCY }}
          OCI_CLI_USER: ${{ secrets.OCI_USER }}
          OCI_CLI_FINGERPRINT: ${{ secrets.OCI_FINGERPRINT }}
          OCI_CLI_KEY_CONTENT: ${{ secrets.OCI_KEY_CONTENT }}
          OCI_CLI_REGION: ${{ secrets.OCI_REGION }}
        run: python oci_cis_scanner.py
```

## Manual Remediation Steps

Some controls require manual intervention:

### MFA (1.2)
1. Go to OCI Console → Identity → Users
2. Select each user → Enable MFA
3. Users must complete MFA setup on next login

### API Key Rotation (1.3)
1. Generate new API keys for users with old keys
2. Update applications using those keys
3. Delete old keys after confirming new keys work

### Security List Hardening (2.1-2.4)
1. Review each flagged security list/NSG
2. Remove or restrict 0.0.0.0/0 ingress rules
3. Add specific CIDR blocks for allowed sources

## Support

For questions about CIS benchmarks:
- [CIS Oracle Cloud Foundation Benchmark](https://www.cisecurity.org/benchmark/oracle_cloud)
- [OCI Security Best Practices](https://docs.oracle.com/en-us/iaas/Content/Security/Concepts/security_guide.htm)
