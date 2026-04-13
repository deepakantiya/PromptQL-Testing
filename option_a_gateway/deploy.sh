#!/bin/bash
#############################################
# Option A: OCI API Gateway Deployment Script
#############################################

set -e

echo "============================================"
echo "OCI API Gateway Proxy - Deployment"
echo "============================================"

# Check prerequisites
echo ""
echo "Checking prerequisites..."

command -v terraform >/dev/null 2>&1 || { echo "❌ Terraform not installed"; exit 1; }
echo "✅ Terraform"

command -v fn >/dev/null 2>&1 || { echo "❌ Fn CLI not installed. Install: brew install fn"; exit 1; }
echo "✅ Fn CLI"

command -v docker >/dev/null 2>&1 || { echo "❌ Docker not installed"; exit 1; }
echo "✅ Docker"

command -v oci >/dev/null 2>&1 || { echo "❌ OCI CLI not installed"; exit 1; }
echo "✅ OCI CLI"

# Read variables
source <(grep -E '^[a-z_]+=' terraform.tfvars | sed 's/ *= */=/g' | tr -d '"')

if [ -z "$tenancy_ocid" ]; then
    echo "❌ Please fill in terraform.tfvars first!"
    exit 1
fi

REGION=${region:-us-sanjose-1}
COMPARTMENT=${compartment_ocid}

echo ""
echo "Region: $REGION"
echo "Compartment: $COMPARTMENT"

# Step 1: Deploy base infrastructure
echo ""
echo "============================================"
echo "Step 1: Deploying base infrastructure..."
echo "============================================"

terraform init
terraform apply -target=oci_core_vcn.proxy_vcn -target=oci_core_subnet.proxy_subnet -target=oci_artifacts_container_repository.function_repo -target=oci_functions_application.proxy_app -target=oci_identity_dynamic_group.functions_dg -target=oci_identity_policy.functions_policy -auto-approve

NAMESPACE=$(terraform output -raw namespace)
APP_OCID=$(terraform output -raw function_app_ocid)

echo ""
echo "Namespace: $NAMESPACE"
echo "App OCID: $APP_OCID"

# Step 2: Build and deploy functions
echo ""
echo "============================================"
echo "Step 2: Building and deploying functions..."
echo "============================================"

# Login to OCIR
echo "Logging into OCI Container Registry..."
docker login ${REGION}.ocir.io

# Configure Fn
fn create context oci-proxy --provider oracle 2>/dev/null || true
fn use context oci-proxy
fn update context oracle.compartment-id $COMPARTMENT
fn update context api-url https://functions.${REGION}.oci.oraclecloud.com
fn update context registry ${REGION}.ocir.io/${NAMESPACE}

FUNCTIONS=("identity_handler" "network_handler" "storage_handler" "compute_handler" "security_handler")
declare -A FUNCTION_OCIDS

for func in "${FUNCTIONS[@]}"; do
    echo ""
    echo "Building $func..."
    cd functions/$func
    fn build
    
    # Tag and push
    FUNC_NAME=$(echo $func | tr '_' '-')
    IMAGE="${REGION}.ocir.io/${NAMESPACE}/${FUNC_NAME}:0.0.1"
    docker tag ${FUNC_NAME}:0.0.1 $IMAGE
    docker push $IMAGE
    
    # Deploy function
    fn deploy --app oci-proxy-app --no-bump
    
    # Get function OCID
    FUNC_OCID=$(fn inspect function oci-proxy-app $FUNC_NAME | grep -o 'ocid1.fnfunc[^"]*' | head -1)
    FUNCTION_OCIDS[$func]=$FUNC_OCID
    echo "Deployed $func: $FUNC_OCID"
    
    cd ../..
done

# Step 3: Update Terraform with function OCIDs
echo ""
echo "============================================"
echo "Step 3: Updating API Gateway routes..."
echo "============================================"

# Replace placeholders in main.tf with actual function OCIDs
sed -i.bak "s/PLACEHOLDER_IDENTITY_FUNC/${FUNCTION_OCIDS[identity_handler]}/g" main.tf
sed -i.bak "s/PLACEHOLDER_NETWORK_FUNC/${FUNCTION_OCIDS[network_handler]}/g" main.tf
sed -i.bak "s/PLACEHOLDER_STORAGE_FUNC/${FUNCTION_OCIDS[storage_handler]}/g" main.tf
sed -i.bak "s/PLACEHOLDER_COMPUTE_FUNC/${FUNCTION_OCIDS[compute_handler]}/g" main.tf
sed -i.bak "s/PLACEHOLDER_SECURITY_FUNC/${FUNCTION_OCIDS[security_handler]}/g" main.tf
sed -i.bak "s/PLACEHOLDER_CIS_FUNC/${FUNCTION_OCIDS[identity_handler]}/g" main.tf  # CIS uses identity handler

# Apply final configuration
terraform apply -auto-approve

# Step 5: Output results
echo ""
echo "============================================"
echo "✅ DEPLOYMENT COMPLETE!"
echo "============================================"
echo ""
terraform output api_gateway_endpoint
echo ""
echo "API Key (save this!):"
terraform output api_key
echo ""
terraform output available_endpoints
echo ""
echo "============================================"
echo "NEXT: Create Custom Integration in PromptQL"
echo "============================================"
echo "1. Go to My Data → Add Custom Integration"
echo "2. Provider ID: oci_proxy"
echo "3. Base URL: $(terraform output -raw api_gateway_endpoint | sed 's|/api/v1||')"
echo "4. Auth: API Key (x-api-key header)"
echo "5. API Key: <copy from above>"
echo ""
