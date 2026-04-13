#!/bin/bash
#############################################
# OCI CIS Scanner - Deployment Script
# Region: us-sanjose-1
#############################################

set -e

REGION="us-sanjose-1"
COMPARTMENT_OCID="ocid1.compartment.oc1..aaaaaaaahfbah4laitygyef5ufrcv4xmfzvewnae7atcwvy7vryipdzu2s4q"

echo "============================================"
echo "OCI CIS Benchmark Scanner Deployment"
echo "Region: $REGION"
echo "============================================"

# Step 1: Check prerequisites
echo ""
echo "[1/6] Checking prerequisites..."
command -v terraform >/dev/null 2>&1 || { echo "ERROR: terraform is required but not installed."; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "ERROR: docker is required but not installed."; exit 1; }
command -v fn >/dev/null 2>&1 || { echo "ERROR: Fn CLI is required but not installed. Install with: brew install fn"; exit 1; }
command -v oci >/dev/null 2>&1 || { echo "ERROR: OCI CLI is required but not installed."; exit 1; }
echo "✓ All prerequisites installed"

# Step 2: Verify terraform.tfvars
echo ""
echo "[2/6] Checking configuration..."
cd oci_function_terraform

if [ ! -f terraform.tfvars ]; then
    echo "ERROR: terraform.tfvars not found. Copy from template and fill in your values:"
    echo "  cp terraform.tfvars.template terraform.tfvars"
    exit 1
fi

# Check if placeholder values are still there
if grep -q "YOUR_TENANCY_ID" terraform.tfvars; then
    echo "ERROR: Please update terraform.tfvars with your actual OCI credentials"
    exit 1
fi
echo "✓ Configuration looks valid"

# Step 3: Deploy infrastructure
echo ""
echo "[3/6] Deploying infrastructure with Terraform..."
terraform init
terraform apply -auto-approve

# Capture outputs
GATEWAY_ENDPOINT=$(terraform output -raw api_gateway_endpoint 2>/dev/null || echo "")
API_KEY=$(terraform output -raw api_key 2>/dev/null || echo "")
NAMESPACE=$(terraform output -raw namespace 2>/dev/null || echo "")
APP_OCID=$(terraform output -raw function_app_ocid 2>/dev/null || echo "")

cd ..

# Step 4: Build and push function
echo ""
echo "[4/6] Building and deploying function..."
cd oci_function

# Login to OCI Registry
echo "Logging into OCI Container Registry..."
echo "You will be prompted for your Auth Token (generate at OCI Console > Your User > Auth Tokens)"
docker login ${REGION}.ocir.io

# Build function
echo "Building function..."
fn build

# Tag and push
IMAGE_TAG="${REGION}.ocir.io/${NAMESPACE}/cis-benchmark-scanner:0.0.1"
docker tag cis-benchmark-scanner:0.0.1 $IMAGE_TAG
docker push $IMAGE_TAG

# Create/update function
echo "Deploying function to OCI..."
fn create context oci-cis --provider oracle
fn use context oci-cis
fn update context oracle.compartment-id $COMPARTMENT_OCID
fn update context api-url https://functions.${REGION}.oci.oraclecloud.com
fn update context registry ${REGION}.ocir.io/${NAMESPACE}

# Deploy
fn deploy --app cis-benchmark-scanner --no-bump

cd ..

# Step 5: Test deployment
echo ""
echo "[5/6] Testing deployment..."
sleep 5

TEST_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "https://${GATEWAY_ENDPOINT}" \
    -H "x-api-key: ${API_KEY}" \
    -H "Content-Type: application/json")

if [ "$TEST_RESPONSE" = "200" ] || [ "$TEST_RESPONSE" = "201" ]; then
    echo "✓ Function is responding correctly"
else
    echo "⚠ Function returned HTTP $TEST_RESPONSE - may need more time to warm up"
fi

# Step 6: Done!
echo ""
echo "============================================"
echo "✅ Deployment Complete!"
echo "============================================"
echo ""
echo "API Gateway Endpoint: https://${GATEWAY_ENDPOINT}"
echo "API Key: ${API_KEY}"
echo ""
echo "Test with:"
echo "  curl -X POST https://${GATEWAY_ENDPOINT} \\"
echo "    -H 'x-api-key: ${API_KEY}' \\"
echo "    -H 'Content-Type: application/json'"
echo ""
echo "============================================"
echo "Next: Create Custom Integration in PromptQL"
echo "============================================"
echo ""
echo "1. Go to PromptQL → My Data → Add Custom Integration"
echo "2. Configure:"
echo "   - Name: OCI CIS Scanner"
echo "   - Provider ID: oci_cis_scanner"
echo "   - Base URL: https://$(echo $GATEWAY_ENDPOINT | cut -d'/' -f1)"
echo "   - Authentication: API Key"
echo "   - API Key Header: x-api-key"
echo "   - API Key: ${API_KEY}"
echo "3. Click Connect"
echo ""
echo "Then tell PromptQL: 'Run the OCI CIS benchmark scan'"
