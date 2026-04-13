# OCI CIS Scanner Function - Your Configuration
# ==================================================
# Region: us-sanjose-1
# Compartment: (provided by user)

# Your OCI region
region = "us-sanjose-1"

# Compartment to deploy resources into
compartment_ocid = "ocid1.compartment.oc1..aaaaaaaahfbah4laitygyef5ufrcv4xmfzvewnae7atcwvy7vryipdzu2s4q"

# ============================================
# FILL IN THESE VALUES FROM YOUR OCI ACCOUNT
# ============================================

# Your tenancy OCID
# Found at: OCI Console → Administration → Tenancy Details
tenancy_ocid = "ocid1.tenancy.oc1..<YOUR_TENANCY_ID>"

# Your user OCID  
# Found at: OCI Console → Identity → Users → Your User
user_ocid = "ocid1.user.oc1..<YOUR_USER_ID>"

# API key fingerprint
# Found at: Your User → API Keys
fingerprint = "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99"

# Path to your API private key file
private_key_path = "~/.oci/oci_api_key.pem"

# Optional: Custom API key for function authentication
# Leave commented to auto-generate a secure random key
# function_api_key = "your-custom-api-key"
