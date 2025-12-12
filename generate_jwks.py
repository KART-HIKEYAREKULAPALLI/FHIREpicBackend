import json
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# --- CONFIGURATION ---
KEY_FILE = 'private_key_cerner.pem'  # Your private key file
KEY_ID = 'cerner-key-1'       # This MUST match what you put in config.json
# ---------------------

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string."""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

try:
    # 1. Load the Private Key
    with open(KEY_FILE, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    # 2. Get Public Numbers (n and e)
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    
    n_encoded = int_to_base64(public_numbers.n)
    e_encoded = int_to_base64(public_numbers.e)

    # 3. Create the JWKS Structure
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": KEY_ID,
                "alg": "RS384",
                "n": n_encoded,
                "e": e_encoded
            }
        ]
    }

    # 4. Print the result
    print("\nSUCCESS! Copy the JSON below into your jwks.json file:\n")
    print(json.dumps(jwks, indent=2))

except FileNotFoundError:
    print(f"Error: Could not find '{KEY_FILE}'. Make sure you generated it with OpenSSL first.")
except Exception as e:
    print(f"Error: {e}")