import executor
from executor import aio

async def main():
    # Check what integrations are available in this project
    from promptql.playground import query_graphql
    
    result = await query_graphql("""
        { 
            saas_integrations_project_integrations {
                provider_id
                enabled
                provider {
                    name
                    type
                    base_url
                    is_preset
                }
            }
        }
    """)
    
    integrations = result.get("saas_integrations_project_integrations", [])
    
    if integrations:
        print("Available integrations in this project:")
        for integration in integrations:
            provider = integration.get("provider", {})
            print(f"  - Provider ID: {integration.get('provider_id')}")
            print(f"    Name: {provider.get('name')}")
            print(f"    Enabled: {integration.get('enabled')}")
            print(f"    Base URL: {provider.get('base_url')}")
            print()
    else:
        print("No integrations found in this project.")
        print("\nNote: OCI SDK typically requires direct API access, not a SaaS integration.")