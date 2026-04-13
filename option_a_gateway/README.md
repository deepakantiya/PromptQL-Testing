# Option A: OCI API Gateway Proxy

This approach creates an API Gateway that proxies requests to OCI APIs, giving PromptQL real-time access to query and interact with your OCI tenancy.

## Architecture

```
[PromptQL] --API Key--> [OCI API Gateway] --Routes--> [OCI Functions] --Resource Principal--> [OCI Services]
```

**Benefits over Option B (single function):**
- ✅ Real-time queries to any OCI service
- ✅ Modular - add new endpoints easily
- ✅ Lower latency for simple queries
- ✅ Can add write operations for remediation later
- ✅ Better debugging - each service isolated

## Available Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/identity/users` | GET | List all users with MFA & API key info |
| `/api/v1/identity/groups` | GET | List all groups with member counts |
| `/api/v1/identity/policies` | GET | List all IAM policies |
| `/api/v1/identity/compartments` | GET | List compartments |
| `/api/v1/identity/auth-policy` | GET | Get password policy (CIS 1.4-1.6) |
| `/api/v1/network/vcns` | GET | List VCNs |
| `/api/v1/network/security-lists` | GET | Security lists with SSH/RDP flags |
| `/api/v1/network/nsgs` | GET | NSGs with unrestricted ingress flags |
| `/api/v1/storage/buckets` | GET | Buckets with public access status |
| `/api/v1/compute/instances` | GET | List compute instances |
| `/api/v1/compute/volumes` | GET | Volumes with encryption status |
| `/api/v1/security/cloud-guard/status` | GET | Cloud Guard enabled check |
| `/api/v1/security/cloud-guard/problems` | GET | Active security findings |
| `/api/v1/cis/scan` | POST | Run full CIS benchmark scan |

## Deployment

```bash
# 1. Configure credentials
cp terraform.tfvars.template terraform.tfvars
# Edit terraform.tfvars

# 2. Run deployment
chmod +x deploy.sh
./deploy.sh
```

## Directory Structure

```
option_a_gateway/
├── main.tf                # Terraform configuration (edit this)
├── terraform.tfvars       # Your configuration (edit this)
├── deploy.sh              # Deployment script
├── README.md              # This file
└── functions/
    ├── identity_handler/  # IAM operations
    ├── network_handler/   # VCN/security operations
    ├── storage_handler/   # Object storage operations
    ├── compute_handler/   # Compute/volume operations
    └── security_handler/  # Cloud Guard operations
```

## Cost Estimate

- **API Gateway:** ~$3/million API calls
- **Functions:** ~$0.20/million invocations + $0.00001417/GB-second
- **Estimated monthly:** < $5 for typical usage

## Adding New Endpoints

1. Create new function in `functions/new_handler/`
2. Add route in `main.tf` under `oci_apigateway_deployment`
3. Deploy: `cd functions/new_handler && fn deploy --app oci-proxy-app`
4. Update Terraform: `terraform apply`

## Security Notes

- Functions use **Resource Principals** (no stored credentials)
- API Gateway validates API key before routing
- IAM policies grant **read-only** access
- All traffic over HTTPS
