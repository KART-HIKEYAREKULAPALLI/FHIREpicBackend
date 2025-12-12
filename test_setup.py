"""
Test Script for Epic FHIR Lab Report Service (Bulk Data Version)

This script tests the Bulk Data Access components:
1. Configuration & Auth
2. Initiating a Bulk Export ($export)
3. Checking Export Status
4. Email connectivity
"""

import json
import sys
import time
from pathlib import Path

def test_config():
    """Test that configuration file exists and is valid."""
    print("\n" + "="*50)
    print("TESTING CONFIGURATION")
    print("="*50)
    
    config_path = Path("config.json")
    if not config_path.exists():
        print("❌ config.json not found!")
        print("   Please copy config.example.json to config.json and fill in your values.")
        return None
    
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        print("✓ config.json loaded successfully")
        
        # Check required fields
        required_epic = ["client_id", "private_key_path", "token_url", "fhir_base_url"]
        required_email = ["smtp_host", "smtp_port", "smtp_user", "smtp_password", "from_email", "to_email"]
        
        for field in required_epic:
            if field not in config.get("epic", {}):
                print(f"❌ Missing epic.{field} in config")
                return None
        print("✓ Epic configuration fields present")
        
        # Check key_id (important for JWT header)
        if "key_id" not in config.get("epic", {}):
            print("⚠ WARNING: epic.key_id not set!")
            print("  The 'kid' (key ID) in your JWT header MUST match your JWKS.")
            print("  Based on your JWKS, add this to your config.json:")
            print('  "key_id": "myapp"')
        else:
            print(f"✓ Key ID (kid) set to: {config['epic']['key_id']}")

        # CRITICAL: Check for group_id (Required for Bulk Data)
        if "group_id" not in config or not config["group_id"]:
            print("❌ Missing 'group_id' in config!")
            print("   The Bulk Data API requires a specific Group ID to export data from.")
            return None
        print(f"✓ Group ID present: {config['group_id']}")
        
        for field in required_email:
            if field not in config.get("email", {}):
                print(f"❌ Missing email.{field} in config")
                return None
        print("✓ Email configuration fields present")
        
        return config
        
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON in config.json: {e}")
        return None


def test_private_key(config):
    """Test that private key exists and is readable."""
    print("\n" + "="*50)
    print("TESTING PRIVATE KEY")
    print("="*50)
    
    key_path = Path(config["epic"]["private_key_path"])
    if not key_path.exists():
        print(f"❌ Private key not found at: {key_path}")
        print("   Please copy your private key to the specified location.")
        return False
    
    try:
        with open(key_path, 'r') as f:
            key_content = f.read()
        
        if "PRIVATE KEY" not in key_content:
            print("❌ File doesn't appear to be a valid PEM private key")
            return False
        
        print("✓ Private key file found and readable")
        return True
        
    except Exception as e:
        print(f"❌ Error reading private key: {e}")
        return False


def test_jwt_creation(config):
    """Test JWT creation."""
    print("\n" + "="*50)
    print("TESTING JWT CREATION")
    print("="*50)
    
    try:
        import jwt
        import time
        import uuid
        
        with open(config["epic"]["private_key_path"], 'r') as f:
            private_key = f.read()
        
        now = int(time.time())
        claims = {
            "iss": config["epic"]["client_id"],
            "sub": config["epic"]["client_id"],
            "aud": config["epic"]["token_url"],
            "jti": str(uuid.uuid4()),
            "exp": now + 220
        }
        
        key_id = config["epic"].get("key_id", "myapp")
        headers = {
            "alg": "RS384",
            "typ": "JWT",
            "kid": key_id
        }
        
        token = jwt.encode(claims, private_key, algorithm="RS384", headers=headers)
        
        print("✓ JWT created successfully")
        
        # Decode header to verify
        header = jwt.get_unverified_header(token)
        if header.get('kid'):
            print("  ✓ kid is present in JWT header (required by Epic)")
        else:
            print("  ✗ kid is MISSING from JWT header!")
        
        return True
        
    except Exception as e:
        print(f"❌ JWT creation failed: {e}")
        return False


def test_authentication(config):
    """Test Epic authentication."""
    print("\n" + "="*50)
    print("TESTING EPIC AUTHENTICATION")
    print("="*50)
    
    try:
        from epic_fhir_client import EpicFHIRClient
        
        client = EpicFHIRClient(config["epic"])
        
        if client.authenticate():
            print("✓ Authentication successful!")
            print(f"  Token expires at: {client.token_expiry}")
            return client
        else:
            print("❌ Authentication failed")
            return None
            
    except Exception as e:
        print(f"❌ Authentication error: {e}")
        return None


def test_bulk_export_capabilities(client, config):
    """
    Test the Bulk Data Export initialization.
    Does NOT wait for the full download (that takes too long for a unit test),
    but verifies we can Start and Monitor the job.
    """
    print("\n" + "="*50)
    print("TESTING BULK DATA EXPORT HANDSHAKE")
    print("="*50)
    
    try:
        group_id = config.get("group_id")
        
        print(f"1. Attempting to START bulk export for Group/{group_id}...")
        
        # Test initiating the export
        status_url = client.start_bulk_export(group_id, hours_back=24)
        
        if status_url:
            print("✓ Bulk export initiated successfully!")
            print(f"  Status URL: {status_url}")
            
            # Test checking the status
            print("\n2. Checking export status (Polling once)...")
            manifest = client.check_export_status(status_url)
            
            if manifest is None:
                print("✓ Status check successful: Received 202 Accepted (Job is running)")
            elif "output" in manifest:
                 print("✓ Status check successful: Job completed immediately (Rare, but good)")
            elif "error" in manifest:
                 print(f"❌ Status check returned error: {manifest['error']}")
                 return False
            
            print("\nNOTE: We will not wait for the full download in this quick test.")
            print("      Run the full integration test to download and parse NDJSON files.")
            return True
        else:
            print("❌ Failed to initiate bulk export. Check client logs.")
            return False
            
    except Exception as e:
        print(f"❌ Bulk Data test error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_email(config):
    """Test email sending."""
    print("\n" + "="*50)
    print("TESTING EMAIL (SMTP)")
    print("="*50)
    
    try:
        from epic_fhir_client import EmailSender
        
        sender = EmailSender(config["email"])
        
        test_subject = "Epic FHIR Test"
        test_text = "Test email from setup script."
        test_html = "<html><body><h1>Test</h1></body></html>"
        
        print(f"Sending test email to: {config['email']['to_email']}")
        
        if sender.send_email(test_subject, test_text, test_html):
            print("✓ Test email sent successfully!")
            return True
        else:
            print("❌ Failed to send test email")
            return False
            
    except Exception as e:
        print(f"❌ Email error: {e}")
        return False


def run_full_test():
    """Run the complete logic using the LabReportService."""
    print("\n" + "="*50)
    print("RUNNING FULL INTEGRATION TEST")
    print("WARNING: This may take several minutes to complete the Bulk Export.")
    print("="*50)
    
    try:
        from epic_fhir_client import EpicFHIRClient, EmailSender, LabReportService, load_config
        
        config = load_config()
        
        fhir_client = EpicFHIRClient(config["epic"])
        email_sender = EmailSender(config["email"])
        group_id = config.get("group_id")
        
        service = LabReportService(fhir_client, email_sender, group_id=group_id)
        
        print(f"Starting service for Group: {group_id}")
        service.process_and_send_reports()
        print("✓ Full test completed!")
        
        return True
        
    except Exception as e:
        print(f"❌ Full test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Main test runner."""
    print("\n" + "#"*60)
    print("#  EPIC FHIR BULK DATA SERVICE - TEST SUITE")
    print("#"*60)
    
    # Run Checks
    config = test_config()
    if not config: sys.exit(1)
    
    if not test_private_key(config): sys.exit(1)
    if not test_jwt_creation(config): sys.exit(1)
    
    client = test_authentication(config)
    if not client: sys.exit(1)
    
    # Test Bulk Data Handshake
    bulk_ok = test_bulk_export_capabilities(client, config)
    
    # Test Email
    test_email(config)
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print("✓ Config & Keys: OK")
    print("✓ Authentication: OK")
    print(f"✓ Bulk Data API: {'OK' if bulk_ok else 'FAILED'}")
    
    if bulk_ok:
        print("\nReady for deployment.")
        print("-" * 30)
        response = input("Do you want to run the FULL Integration Test?\n(This will wait for the Bulk Export to finish, download NDJSON, and send the email) [y/N]: ")
        if response.lower() == 'y':
            run_full_test()
    else:
        print("\n❌ Please fix the Bulk Data API errors before running the full test.")

if __name__ == "__main__":
    #main()
    config = test_config()
    if not config: sys.exit(1)
    
    if not test_private_key(config): sys.exit(1)
    if not test_jwt_creation(config): sys.exit(1)
    
    client = test_authentication(config)
    if not client: sys.exit(1)
    
