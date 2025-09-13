#!/usr/bin/env python3

import sys
sys.path.append('.')

from security.signatures import SmartContractSigner, SignatureData
from security.cryptography import ECDSAKeyPair
import base64

# Create test data
contract_data = {
    'bytecode': '608060405234801561001057600080fd5b50',
    'constructor_args': [],
    'deployer': '0x123'
}

# Create key pair and signer
key_pair = ECDSAKeyPair.generate()
contract_signer = SmartContractSigner()

# Get private key for signing
private_key_hex = key_pair.get_private_key_hex()
print(f"Private key hex: {private_key_hex[:20]}...")

# Sign contract
signature_data = contract_signer.sign_contract(contract_data, private_key_hex)
print(f"Signature created: {signature_data.signature[:20]}...")
print(f"Public key: {signature_data.public_key[:50]}...")
print(f"Address: {signature_data.address}")

# Try to verify with detailed debugging
print("\n=== Debugging verification ===")

# Recreate the message manually to check
message_parts = [
    contract_data.get('bytecode', ''),
    str(contract_data.get('constructor_args', [])),
    contract_data.get('deployer', '')
]
message = '|'.join(message_parts).encode('utf-8')
print(f"Message to verify: {message}")
print(f"Message length: {len(message)}")

# Check if we can recreate the same signature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
import base64

try:
    # Load the public key from signature data
    public_key_bytes = base64.b64decode(signature_data.public_key)
    public_key = serialization.load_pem_public_key(public_key_bytes)
    print(f"Public key loaded successfully")
    
    # Decode the signature
    signature_bytes = base64.b64decode(signature_data.signature)
    print(f"Signature decoded, length: {len(signature_bytes)}")
    
    # Try verification
    public_key.verify(signature_bytes, message, ec.ECDSA(hashes.SHA256()))
    print("Direct verification: SUCCESS")
    
except Exception as e:
    print(f"Direct verification failed: {e}")
    import traceback
    traceback.print_exc()

# Now try the contract signer method
try:
    is_valid = contract_signer.verify_contract_signature(contract_data, signature_data)
    print(f"Contract signer verification result: {is_valid}")
except Exception as e:
    print(f"Contract signer verification error: {e}")
    import traceback
    traceback.print_exc()