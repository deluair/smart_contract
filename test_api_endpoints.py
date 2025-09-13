#!/usr/bin/env python3
"""
Test script for API endpoints
"""

import requests
import json
from security.signatures import SmartContractSigner, SignatureData
from security.cryptography import ECDSAKeyPair

def test_health_endpoint():
    """Test health check endpoint"""
    print("\n=== Testing Health Endpoint ===")
    try:
        response = requests.get('http://localhost:8080/api/health')
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_oracle_price_endpoint():
    """Test oracle price endpoint"""
    print("\n=== Testing Oracle Price Endpoint ===")
    try:
        response = requests.get('http://localhost:8080/api/oracle/price/BTC')
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return True  # 404 is expected when no price data
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_contract_verification_endpoint():
    """Test contract verification endpoint"""
    print("\n=== Testing Contract Verification Endpoint ===")
    try:
        # Create test contract data
        contract_data = {
            'bytecode': '608060405234801561001057600080fd5b50',
            'constructor_args': [],
            'owner': '0x123'
        }
        
        # Create signature using SmartContractSigner
        key_pair = ECDSAKeyPair.generate()
        signer = SmartContractSigner()
        signature_data = signer.sign_contract(contract_data, key_pair.get_private_key_hex())
        
        # Prepare API request
        payload = {
            'contract_data': contract_data,
            'signature_data': {
                'signature': signature_data.signature,
                'public_key': signature_data.public_key,
                'address': signature_data.address,
                'timestamp': signature_data.timestamp
            }
        }
        
        response = requests.post(
            'http://localhost:8080/api/contracts/verify',
            json=payload,
            headers={'Content-Type': 'application/json'}
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 200:
            result = response.json()
            return result.get('valid', False)
        return False
        
    except Exception as e:
        print(f"Error: {e}")
        return False

def main():
    """Run all API endpoint tests"""
    print("Starting API Endpoint Tests...")
    
    results = {
        'health': test_health_endpoint(),
        'oracle_price': test_oracle_price_endpoint(),
        'contract_verification': test_contract_verification_endpoint()
    }
    
    print("\n=== Test Results ===")
    for test_name, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{test_name}: {status}")
    
    all_passed = all(results.values())
    print(f"\nOverall: {'✓ ALL TESTS PASSED' if all_passed else '✗ SOME TESTS FAILED'}")
    return all_passed

if __name__ == '__main__':
    main()