import executor
"""
OCI Integration Setup Test
==========================
This script checks what capabilities we have for OCI integration
and guides the user through providing credentials.
"""
from executor import aio
import hashlib
import base64
import json
from datetime import datetime, timezone

async def main():
    print("=" * 60)
    print("OCI Integration Setup for PromptQL")
    print("=" * 60)
    
    # Check available libraries for cryptography
    print("\n[1] Checking available libraries...")
    
    available_libs = {}
    
    try:
        import cryptography
        available_libs['cryptography'] = True
        print("  ✅ cryptography - available")
    except ImportError:
        available_libs['cryptography'] = False
        print("  ❌ cryptography - not available")
    
    try:
        import rsa
        available_libs['rsa'] = True
        print("  ✅ rsa - available")
    except ImportError:
        available_libs['rsa'] = False
        print("  ❌ rsa - not available")
    
    try:
        from Crypto.Signature import pkcs1_15
        available_libs['pycryptodome'] = True
        print("  ✅ pycryptodome - available")
    except ImportError:
        available_libs['pycryptodome'] = False
        print("  ❌ pycryptodome - not available")
    
    # Standard library always available
    print("  ✅ hashlib - available (standard library)")
    print("  ✅ base64 - available (standard library)")
    
    has_crypto = any([available_libs.get('cryptography'), 
                      available_libs.get('rsa'), 
                      available_libs.get('pycryptodome')])
    
    print("\n[2] Assessment...")
    if has_crypto:
        print("  ✅ RSA signing capability available!")
        print("  We can implement native OCI request signing.")
    else:
        print("  ⚠️  No RSA signing library available.")
        print("  We'll need to use an alternative approach.")
    
    print("\n" + "=" * 60)
    print("OCI CREDENTIALS REQUIRED")
    print("=" * 60)
    print("""
To connect PromptQL to your OCI tenancy, you'll need:

1. TENANCY OCID
   - Found in: OCI Console → Administration → Tenancy Details
   - Format: ocid1.tenancy.oc1..aaaaaaa...

2. USER OCID  
   - Found in: OCI Console → Identity → Users → Your User
   - Format: ocid1.user.oc1..aaaaaaa...

3. API KEY FINGERPRINT
   - Found in: Your User → API Keys
   - Format: aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99

4. REGION
   - Your OCI region identifier
   - Examples: us-ashburn-1, us-phoenix-1, eu-frankfurt-1

5. PRIVATE KEY (PEM format)
   - The private key associated with your API key
   - Should start with: -----BEGIN RSA PRIVATE KEY-----
   - Or: -----BEGIN PRIVATE KEY-----

SECURITY NOTE: 
The private key will be stored securely in this thread's context.
Only you have access to this thread.
""")
    
    # Store test results
    await aio.store_artifact(
        identifier='oci_setup_status',
        title='OCI Setup Status',
        artifact_type='text',
        data=json.dumps({
            'has_crypto': has_crypto,
            'available_libs': available_libs,
            'ready_for_native_signing': has_crypto
        }, indent=2),
        metadata={'text': {'content_type': 'application/json'}}
    )
    
    print("\n" + "=" * 60)
    print("NEXT STEPS")
    print("=" * 60)
    if has_crypto:
        print("""
Please provide your OCI credentials in this format:

```
TENANCY_OCID: ocid1.tenancy.oc1..your-tenancy-id
USER_OCID: ocid1.user.oc1..your-user-id  
FINGERPRINT: aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99
REGION: us-ashburn-1
PRIVATE_KEY:
-----BEGIN RSA PRIVATE KEY-----
your-private-key-content
-----END RSA PRIVATE KEY-----
```

Once you provide these, I'll:
1. Securely store the credentials
2. Test the connection
3. Run the CIS benchmark scanner
""")
    else:
        print("""
Since native RSA signing isn't available, here are your options:

OPTION A: Provide an OCI API Gateway Endpoint
  - Create an API Gateway in OCI with IAM authentication
  - The gateway can use resource/instance principals
  - Provide us the endpoint URL and any API key

OPTION B: Use OCI Cloud Shell Token
  - Generate a session token from OCI Cloud Shell
  - Provide the token (valid for limited time)

OPTION C: Deploy a simple OCI Function
  - I can provide you a function that wraps the OCI APIs
  - The function uses resource principals
  - Accessible via HTTP

Please let me know which option works best for you!
""")