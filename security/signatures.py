import hashlib
import json
import time
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from .cryptography import ECDSAKeyPair, CryptoUtils, MultiSignature
import base64


@dataclass
class SignatureData:
    """Container for signature information"""
    signature: str
    public_key: str
    address: str
    timestamp: float
    algorithm: str = "ECDSA-SHA256"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'signature': self.signature,
            'public_key': self.public_key,
            'address': self.address,
            'timestamp': self.timestamp,
            'algorithm': self.algorithm
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SignatureData':
        return cls(
            signature=data['signature'],
            public_key=data['public_key'],
            address=data['address'],
            timestamp=data['timestamp'],
            algorithm=data.get('algorithm', 'ECDSA-SHA256')
        )


class TransactionSigner:
    """Handles transaction signing and verification"""
    
    def __init__(self):
        self.key_pairs: Dict[str, ECDSAKeyPair] = {}
    
    def add_key_pair(self, address: str, key_pair: ECDSAKeyPair):
        """Add a key pair for signing"""
        self.key_pairs[address] = key_pair
    
    def sign_transaction(self, transaction_data: Dict[str, Any], signer_address: str) -> Optional[SignatureData]:
        """Sign a transaction with the specified address"""
        if signer_address not in self.key_pairs:
            return None
        
        key_pair = self.key_pairs[signer_address]
        
        # Create canonical transaction string for signing
        canonical_tx = self._create_canonical_transaction(transaction_data)
        message_hash = hashlib.sha256(canonical_tx.encode()).digest()
        
        # Sign the hash
        signature = key_pair.sign(message_hash)
        
        return SignatureData(
            signature=base64.b64encode(signature).decode(),
            public_key=key_pair.export_public_key(),
            address=key_pair.get_address(),
            timestamp=time.time()
        )
    
    def verify_transaction_signature(self, transaction_data: Dict[str, Any], signature_data: SignatureData) -> bool:
        """Verify a transaction signature"""
        try:
            # Recreate canonical transaction string
            canonical_tx = self._create_canonical_transaction(transaction_data)
            message_hash = hashlib.sha256(canonical_tx.encode()).digest()
            
            # Load public key and verify
            from cryptography.hazmat.primitives import serialization, hashes
            from cryptography.hazmat.primitives.asymmetric import ec
            
            public_key_bytes = base64.b64decode(signature_data.public_key)
            public_key = serialization.load_pem_public_key(public_key_bytes)
            signature = base64.b64decode(signature_data.signature)
            
            public_key.verify(signature, message_hash, ec.ECDSA(hashes.SHA256()))
            
            # Verify address matches public key
            temp_keypair = ECDSAKeyPair()
            temp_keypair.public_key = public_key
            expected_address = temp_keypair.get_address()
            
            return expected_address == signature_data.address
            
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False
    
    def _create_canonical_transaction(self, transaction_data: Dict[str, Any]) -> str:
        """Create canonical string representation of transaction for signing"""
        # Remove signature-related fields for canonical representation
        canonical_data = transaction_data.copy()
        canonical_data.pop('signature', None)
        canonical_data.pop('tx_id', None)
        
        # Sort keys for deterministic output
        return json.dumps(canonical_data, sort_keys=True, separators=(',', ':'))


class BlockSigner:
    """Handles block signing and verification for consensus"""
    
    def __init__(self):
        self.validator_keys: Dict[str, ECDSAKeyPair] = {}
    
    def add_validator(self, validator_address: str, key_pair: ECDSAKeyPair):
        """Add a validator key pair"""
        self.validator_keys[validator_address] = key_pair
    
    def sign_block(self, block_data: Dict[str, Any], validator_address: str) -> Optional[SignatureData]:
        """Sign a block as a validator"""
        if validator_address not in self.validator_keys:
            return None
        
        key_pair = self.validator_keys[validator_address]
        
        # Create canonical block string for signing
        canonical_block = self._create_canonical_block(block_data)
        message_hash = hashlib.sha256(canonical_block.encode()).digest()
        
        # Sign the hash
        signature = key_pair.sign(message_hash)
        
        return SignatureData(
            signature=base64.b64encode(signature).decode(),
            public_key=key_pair.export_public_key(),
            address=key_pair.get_address(),
            timestamp=time.time()
        )
    
    def verify_block_signature(self, block_data: Dict[str, Any], signature_data: SignatureData) -> bool:
        """Verify a block signature"""
        try:
            # Recreate canonical block string
            canonical_block = self._create_canonical_block(block_data)
            message_hash = hashlib.sha256(canonical_block.encode()).digest()
            
            # Load public key and verify
            from cryptography.hazmat.primitives import serialization, hashes
            from cryptography.hazmat.primitives.asymmetric import ec
            
            public_key_bytes = base64.b64decode(signature_data.public_key)
            public_key = serialization.load_pem_public_key(public_key_bytes)
            signature = base64.b64decode(signature_data.signature)
            
            public_key.verify(signature, message_hash, ec.ECDSA(hashes.SHA256()))
            return True
            
        except Exception as e:
            print(f"Block signature verification failed: {e}")
            return False
    
    def _create_canonical_block(self, block_data: Dict[str, Any]) -> str:
        """Create canonical string representation of block for signing"""
        # Include only essential block data for signing
        canonical_data = {
            'previous_hash': block_data.get('header', {}).get('previous_hash'),
            'merkle_root': block_data.get('header', {}).get('merkle_root'),
            'timestamp': block_data.get('header', {}).get('timestamp'),
            'block_height': block_data.get('block_height'),
            'difficulty': block_data.get('header', {}).get('difficulty')
        }
        
        return json.dumps(canonical_data, sort_keys=True, separators=(',', ':'))


class SmartContractSigner:
    """Handles smart contract deployment and execution signatures"""
    
    def __init__(self):
        self.contract_owners: Dict[str, ECDSAKeyPair] = {}
    
    def add_contract_owner(self, owner_address: str, key_pair: ECDSAKeyPair):
        """Add a contract owner key pair"""
        self.contract_owners[owner_address] = key_pair
    
    def sign_contract_deployment(self, contract_data: Dict[str, Any], owner_address: str) -> Optional[SignatureData]:
        """Sign a smart contract deployment"""
        if owner_address not in self.contract_owners:
            return None
        
        key_pair = self.contract_owners[owner_address]
        
        # Create canonical contract string for signing
        canonical_contract = self._create_canonical_contract(contract_data)
        message_hash = hashlib.sha256(canonical_contract.encode()).digest()
        
        # Sign the hash
        signature = key_pair.sign(message_hash)
        
        return SignatureData(
            signature=base64.b64encode(signature).decode(),
            public_key=key_pair.export_public_key(),
            address=key_pair.get_address(),
            timestamp=time.time()
        )
    
    def sign_contract_call(self, call_data: Dict[str, Any], caller_address: str) -> Optional[SignatureData]:
        """Sign a smart contract function call"""
        if caller_address not in self.contract_owners:
            return None
        
        key_pair = self.contract_owners[caller_address]
        
        # Create canonical call string for signing
        canonical_call = json.dumps(call_data, sort_keys=True, separators=(',', ':'))
        message_hash = hashlib.sha256(canonical_call.encode()).digest()
        
        # Sign the hash
        signature = key_pair.sign(message_hash)
        
        return SignatureData(
            signature=base64.b64encode(signature).decode(),
            public_key=key_pair.export_public_key(),
            address=key_pair.get_address(),
            timestamp=time.time()
        )
    
    def verify_contract_signature(self, contract_data: Dict[str, Any], signature_data: SignatureData) -> bool:
        """Verify a smart contract signature"""
        try:
            # Determine if this is deployment or call
            if 'bytecode' in contract_data:
                canonical_data = self._create_canonical_contract(contract_data)
            else:
                canonical_data = json.dumps(contract_data, sort_keys=True, separators=(',', ':'))
            
            message_hash = hashlib.sha256(canonical_data.encode()).digest()
            
            # Load public key and verify
            from cryptography.hazmat.primitives import serialization, hashes
            from cryptography.hazmat.primitives.asymmetric import ec
            
            public_key_bytes = base64.b64decode(signature_data.public_key)
            public_key = serialization.load_pem_public_key(public_key_bytes)
            signature = base64.b64decode(signature_data.signature)
            
            public_key.verify(signature, message_hash, ec.ECDSA(hashes.SHA256()))
            return True
            
        except Exception as e:
            print(f"Contract signature verification failed: {e}")
            return False
    
    def _create_canonical_contract(self, contract_data: Dict[str, Any]) -> str:
        """Create canonical string representation of contract for signing"""
        canonical_data = {
            'bytecode': contract_data.get('bytecode'),
            'abi': contract_data.get('abi'),
            'constructor_args': contract_data.get('constructor_args', []),
            'gas_limit': contract_data.get('gas_limit'),
            'gas_price': contract_data.get('gas_price')
        }
        
        return json.dumps(canonical_data, sort_keys=True, separators=(',', ':'))


class MultiSigManager:
    """Manager for multi-signature operations"""
    
    def __init__(self):
        self.multisig_configs: Dict[str, MultiSignature] = {}
    
    def create_multisig(self, address: str, required_signatures: int, public_keys: List[ECDSAKeyPair]) -> str:
        """Create a new multi-signature configuration"""
        multisig = MultiSignature(required_signatures, public_keys)
        multisig_address = multisig.create_multisig_address()
        self.multisig_configs[multisig_address] = multisig
        return multisig_address
    
    def sign_multisig_transaction(self, multisig_address: str, transaction_data: Dict[str, Any], 
                                private_keys: List[ECDSAKeyPair]) -> Optional[Dict[str, Any]]:
        """Sign a transaction with multiple signatures"""
        if multisig_address not in self.multisig_configs:
            return None
        
        multisig = self.multisig_configs[multisig_address]
        
        # Create canonical transaction for signing
        canonical_tx = json.dumps(transaction_data, sort_keys=True, separators=(',', ':'))
        message_hash = hashlib.sha256(canonical_tx.encode()).digest()
        
        # Sign with multiple keys
        return multisig.sign_transaction(message_hash, private_keys)
    
    def verify_multisig_transaction(self, multisig_address: str, transaction_data: Dict[str, Any], 
                                  multisig_signature: Dict[str, Any]) -> bool:
        """Verify a multi-signature transaction"""
        if multisig_address not in self.multisig_configs:
            return False
        
        multisig = self.multisig_configs[multisig_address]
        
        # Create canonical transaction for verification
        canonical_tx = json.dumps(transaction_data, sort_keys=True, separators=(',', ':'))
        message_hash = hashlib.sha256(canonical_tx.encode()).digest()
        
        # Verify signatures
        return multisig.verify_transaction(message_hash, multisig_signature)


class SignatureValidator:
    """Comprehensive signature validation system"""
    
    def __init__(self):
        self.transaction_signer = TransactionSigner()
        self.block_signer = BlockSigner()
        self.contract_signer = SmartContractSigner()
        self.multisig_manager = MultiSigManager()
    
    def validate_transaction_signatures(self, transaction: Dict[str, Any]) -> bool:
        """Validate all signatures in a transaction"""
        # Check if transaction has signature
        if 'signature_data' not in transaction:
            return False
        
        signature_data = SignatureData.from_dict(transaction['signature_data'])
        return self.transaction_signer.verify_transaction_signature(transaction, signature_data)
    
    def validate_block_signatures(self, block: Dict[str, Any]) -> bool:
        """Validate block signatures from validators"""
        if 'validator_signatures' not in block:
            return True  # No signatures required for PoW blocks
        
        validator_signatures = block['validator_signatures']
        valid_signatures = 0
        
        for sig_data in validator_signatures:
            signature_data = SignatureData.from_dict(sig_data)
            if self.block_signer.verify_block_signature(block, signature_data):
                valid_signatures += 1
        
        # Require at least 2/3 of validators to sign (for PoS)
        required_signatures = max(1, len(validator_signatures) * 2 // 3)
        return valid_signatures >= required_signatures
    
    def validate_contract_signatures(self, contract_data: Dict[str, Any]) -> bool:
        """Validate smart contract signatures"""
        if 'signature_data' not in contract_data:
            return False
        
        signature_data = SignatureData.from_dict(contract_data['signature_data'])
        return self.contract_signer.verify_contract_signature(contract_data, signature_data)
    
    def validate_multisig_signatures(self, multisig_address: str, transaction_data: Dict[str, Any], 
                                   multisig_signature: Dict[str, Any]) -> bool:
        """Validate multi-signature transaction"""
        return self.multisig_manager.verify_multisig_transaction(
            multisig_address, transaction_data, multisig_signature
        )


class SignatureAggregator:
    """Aggregates and manages multiple signatures for batch verification"""
    
    def __init__(self):
        self.pending_signatures: Dict[str, List[SignatureData]] = {}
    
    def add_signature(self, item_id: str, signature_data: SignatureData):
        """Add a signature for batch processing"""
        if item_id not in self.pending_signatures:
            self.pending_signatures[item_id] = []
        self.pending_signatures[item_id].append(signature_data)
    
    def verify_batch(self, validator: SignatureValidator) -> Dict[str, bool]:
        """Verify all pending signatures in batch"""
        results = {}
        
        for item_id, signatures in self.pending_signatures.items():
            # This is a simplified batch verification
            # In practice, you'd implement more sophisticated batch verification algorithms
            all_valid = True
            for signature in signatures:
                # Verification logic would depend on the type of signature
                # This is a placeholder for actual batch verification
                pass
            results[item_id] = all_valid
        
        # Clear processed signatures
        self.pending_signatures.clear()
        return results
    
    def get_signature_count(self, item_id: str) -> int:
        """Get number of signatures for an item"""
        return len(self.pending_signatures.get(item_id, []))
    
    def clear_signatures(self, item_id: str):
        """Clear signatures for a specific item"""
        if item_id in self.pending_signatures:
            del self.pending_signatures[item_id]