"""
JWT Debug Script for Epic FHIR Authentication

This script helps diagnose JWT authentication issues with Epic's FHIR API.
It generates a JWT and shows all the details for troubleshooting.
"""

import jwt
import time
import uuid
import json
import base64
import requests
from pathlib import Path
from datetime import datetime


def load_config(config_path: str = "config.json") -> dict:
    """Load configuration from JSON file."""
    with open(config_path, 'r') as f:
        return json.load(f)


def decode_jwt_parts(token: str) -> dict:
    """Decode a JWT without verification to inspect its parts."""
    parts = token.split('.')
    if len(parts) != 3:
        return {"error": "Invalid JWT format"}
    
    # Decode header
    header_b64 = parts[0]
    # Add padding if needed
    header_b64 += '=' * (4 - len(header_b64) % 4) if len(header_b64) % 4 else ''
    header = json.loads(base64.urlsafe_b64decode(header_b64))
    
    # Decode payload
    payload_b64 = parts[1]
    payload_b64 += '=' * (4 - len(payload_b64) % 4) if len(payload_b64) % 4 else ''
    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    
    return {
        "header": header,
        "payload": payload,
        "signature": parts[2][:50] + "..." if len(parts[2]) > 50 else parts[2]
    }


def main():
    print("\n" + "="*70)
    print("EPIC FHIR JWT AUTHENTICATION DEBUG TOOL")
    print("="*70)
    
    # Load config
    print("\n[1] Loading configuration...")
    try:
        config = load_config()
        epic_config = config["epic"]
        print(f"    ✓ Client ID: {epic_config['client_id']}")
        print(f"    ✓ Token URL: {epic_config['token_url']}")
        print(f"    ✓ Key ID: {epic_config.get('key_id', 'NOT SET - THIS MAY BE THE ISSUE!')}")
    except Exception as e:
        print(f"    ✗ Error loading config: {e}")
        return
    
    # Load private key
    print("\n[2] Loading private key...")
    key_path = Path(epic_config['private_key_path'])
    try:
        with open(key_path, 'r') as f:
            private_key = f.read()
        print(f"    ✓ Private key loaded from: {key_path}")
        
        # Check key format
        if "BEGIN RSA PRIVATE KEY" in private_key:
            print("    ✓ Key format: PKCS#1 (RSA PRIVATE KEY)")
        elif "BEGIN PRIVATE KEY" in private_key:
            print("    ✓ Key format: PKCS#8 (PRIVATE KEY)")
        else:
            print("    ⚠ Key format: Unknown - may cause issues")
    except Exception as e:
        print(f"    ✗ Error loading key: {e}")
        return
    
    # Generate JWT
    print("\n[3] Generating JWT...")
    now = int(time.time())
    
    claims = {
        "iss": epic_config['client_id'],
        "sub": epic_config['client_id'],
        "aud": epic_config['token_url'],
        "jti": str(uuid.uuid4()),
        "exp": now + 300,
        "nbf": now,
        "iat": now
    }
    
    # Show claims
    print(f"\n    JWT Claims:")
    print(f"    ┌─────────────────────────────────────────────────────────────")
    print(f"    │ iss (issuer):      {claims['iss']}")
    print(f"    │ sub (subject):     {claims['sub']}")
    print(f"    │ aud (audience):    {claims['aud']}")
    print(f"    │ jti (JWT ID):      {claims['jti']}")
    print(f"    │ iat (issued at):   {claims['iat']} ({datetime.fromtimestamp(claims['iat'])})")
    print(f"    │ nbf (not before):  {claims['nbf']} ({datetime.fromtimestamp(claims['nbf'])})")
    print(f"    │ exp (expiration):  {claims['exp']} ({datetime.fromtimestamp(claims['exp'])})")
    print(f"    │ exp - iat:         {claims['exp'] - claims['iat']} seconds (must be <= 300)")
    print(f"    └─────────────────────────────────────────────────────────────")
    
    # Check common issues
    print("\n[4] Checking for common issues...")
    
    # Check exp is epoch time (integer)
    if isinstance(claims['exp'], int) and claims['exp'] > 1000000000:
        print("    ✓ exp is valid Unix epoch timestamp")
    else:
        print("    ✗ exp is NOT a valid Unix epoch timestamp!")
    
    # Check exp is in future
    if claims['exp'] > now:
        print(f"    ✓ exp is in future ({claims['exp'] - now} seconds from now)")
    else:
        print("    ✗ exp is NOT in the future - JWT is already expired!")
    
    # Check exp is within 5 minutes
    if (claims['exp'] - claims['iat']) <= 300:
        print("    ✓ Token lifetime is within 5 minutes")
    else:
        print("    ✗ Token lifetime exceeds 5 minutes - Epic will reject this!")
    
    # Check jti length
    if len(claims['jti']) <= 151:
        print(f"    ✓ jti length is {len(claims['jti'])} (max 151)")
    else:
        print(f"    ✗ jti length is {len(claims['jti'])} - exceeds max 151!")
    
    # Get key_id
    key_id = epic_config.get('key_id')
    if key_id:
        print(f"    ✓ key_id (kid) is set: {key_id}")
    else:
        print("    ⚠ key_id (kid) is NOT set - this is likely your issue!")
        print("      The kid in your JWT header MUST match the kid in your JWKS")
        key_id = "myapp"  # Default based on their JWKS
        print(f"      Using default: {key_id}")
    
    # Create JWT header with kid
    headers = {
        "alg": "RS384",
        "typ": "JWT",
        "kid": key_id
    }
    
    print(f"\n    JWT Header:")
    print(f"    ┌─────────────────────────────────────────────────────────────")
    print(f"    │ alg: {headers['alg']}")
    print(f"    │ typ: {headers['typ']}")
    print(f"    │ kid: {headers['kid']}")
    print(f"    └─────────────────────────────────────────────────────────────")
    
    # Sign the JWT
    print("\n[5] Signing JWT with RS384...")
    try:
        token = jwt.encode(
            claims,
            private_key,
            algorithm="RS384",
            headers=headers
        )
        print(f"    ✓ JWT created successfully")
        print(f"    Token length: {len(token)} characters")
        
        # Decode and verify structure
        decoded = decode_jwt_parts(token)
        print(f"\n    Decoded JWT:")
        print(f"    Header:  {json.dumps(decoded['header'])}")
        print(f"    Payload: {json.dumps(decoded['payload'])}")
        
        # Verify kid is in header
        if decoded['header'].get('kid') == key_id:
            print(f"    ✓ kid in header matches: {key_id}")
        else:
            print(f"    ✗ kid mismatch! Header has: {decoded['header'].get('kid')}")
            
    except Exception as e:
        print(f"    ✗ Error signing JWT: {e}")
        return
    
    # Test authentication
    print("\n[6] Testing Epic authentication...")
    
    data = {
        "grant_type": "client_credentials",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": token
    }
    
    print(f"\n    POST {epic_config['token_url']}")
    print(f"    Content-Type: application/x-www-form-urlencoded")
    print(f"    Body:")
    print(f"      grant_type: {data['grant_type']}")
    print(f"      client_assertion_type: {data['client_assertion_type']}")
    print(f"      client_assertion: {token[:80]}...")
    
    try:
        response = requests.post(
            epic_config['token_url'],
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        
        print(f"\n    Response Status: {response.status_code}")
        print(f"    Response Body: {response.text}")
        
        if response.status_code == 200:
            print("\n    ✓ ✓ ✓ AUTHENTICATION SUCCESSFUL! ✓ ✓ ✓")
            token_data = response.json()
            print(f"    Access Token: {token_data.get('access_token', 'N/A')[:50]}...")
            print(f"    Expires In: {token_data.get('expires_in', 'N/A')} seconds")
        else:
            print("\n    ✗ ✗ ✗ AUTHENTICATION FAILED ✗ ✗ ✗")
            print("\n    Common causes of 'invalid_client' error:")
            print("    1. kid in JWT header doesn't match kid in your JWKS")
            print("    2. Private key doesn't match the public key in JWKS")
            print("    3. Client ID is incorrect (use Non-Production Client ID for sandbox)")
            print("    4. Public key hasn't synced yet (wait up to 60 minutes)")
            print("    5. JWT claims have incorrect values")
            print("    6. Certificate in JWKS has expired (check x5c)")
            
            # Check certificate expiry
            print("\n    Checking your JWKS certificate expiry...")
            try:
                import ssl
                import base64
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                
                # Your x5c from JWKS
                x5c = "MIIDATCCAemgAwIBAgIUcPy43r3jeA6oZppzp4lGoSQem34wDQYJKoZIhvcNAQELBQAwEDEOMAwGA1UEAwwFbXlhcHAwHhcNMjUxMTMwMDMxMTE4WhcNMjUxMjMwMDMxMTE4WjAQMQ4wDAYDVQQDDAVteWFwcDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALV/PvQHLOT1pY/zL67Xa9BO3p8tnQxBp1dhM5Gib2u6odPC4wGoN1Th5ttRRzdI902gg8QVoq19psiCcths3weBQ1rnGawd6+nNKk3/m5pu2h9iNvpr1hBoJiml3lJz9jizNEfzrNdxsY6lpSEEApm1f7JnNCkv1ChR0egDIvLmGJtFSb8J+5qKPgrBXwcdiuOQlN0kX1gM9F/f03nxfuC0Y2NRTcGKIbwBlK7TcHCbgmw5hHhKW6R1y1ut5JIM5pvuxH8e9b0BZcZlxow3y/rr5ODCtpvJMwlbl14IK8dj/y7fEQFevWo91EFJJK91la0c1xGs8Uk2QEh4PQX5vIkCAwEAAaNTMFEwHQYDVR0OBBYEFFSW/Dbqj2xxDI9FSbqDaQ27QWDaMB8GA1UdIwQYMBaAFFSW/Dbqj2xxDI9FSbqDaQ27QWDaMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAJOSsvoX5Y/RBJkhia+B7G3HKAIl2AgemKQON8gp+FyYkk05SWBSObNBzG2steZPnpakpDYKMs2OuArXKvl2uL+2gLk40U4clMBgHfrh+6cozdHf9bnK8xidFHUf7HcCvFpKeGVW4EipE681zL/c3eH9boKSSl+BVBH0OIwPpYQeHPsyZLMDdoQCuHVPqbk3yDddn+m1vVfdj1cHtMti4rpBQ3m/KpCOb9I0LdlQTQrjuwXri93KJ+iXdZ6uHRN5kigt969R2tq7TGH3ng1ky1k3+UAFUrlXetUcRMjlNd3JCXpJ4FnaoslXsO7UYUFeqYXqX1cnQT61p7Y27O7XaNE="
                cert_der = base64.b64decode(x5c)
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                
                print(f"    Certificate valid from: {cert.not_valid_before_utc}")
                print(f"    Certificate valid until: {cert.not_valid_after_utc}")
                
                from datetime import timezone
                now_utc = datetime.now(timezone.utc)
                if now_utc > cert.not_valid_after_utc:
                    print("    ✗ CERTIFICATE HAS EXPIRED! Generate new keys!")
                elif now_utc < cert.not_valid_before_utc:
                    print("    ✗ Certificate not yet valid!")
                else:
                    print("    ✓ Certificate is currently valid")
                    
            except ImportError:
                print("    (Install 'cryptography' package for certificate check)")
            except Exception as e:
                print(f"    Could not check certificate: {e}")
                
    except Exception as e:
        print(f"    ✗ Request error: {e}")
    
    print("\n" + "="*70)
    print("DEBUG COMPLETE")
    print("="*70)
    
    # Print the full token for manual testing
    print("\n[OPTIONAL] Full JWT for manual testing (e.g., in Postman or jwt.io):")
    print("-"*70)
    print(token)
    print("-"*70)


if __name__ == "__main__":
    main()
