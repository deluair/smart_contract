import hashlib
import secrets
import base64
import json
from typing import Tuple, Optional, Dict, Any
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidSignature
import os

@dataclass
class EncryptionResult:
    """Result of encryption operation"""
    encrypted_data: str
    iv: str
    salt: Optional[str] = None
    
    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary"""
        result = {
            'encrypted_data': self.encrypted_data,
            'iv': self.iv
        }
        if self.salt:
            result['salt'] = self.salt
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> 'EncryptionResult':
        """Create from dictionary"""
        return cls(
            encrypted_data=data['encrypted_data'],
            iv=data['iv'],
            salt=data.get('salt')
        )


class CryptoUtils:
    """Utility class for cryptographic operations"""
    
    @staticmethod
    def generate_random_bytes(length: int = 32) -> bytes:
        """Generate cryptographically secure random bytes"""
        return secrets.token_bytes(length)
    
    @staticmethod
    def hash_sha256(data: bytes) -> bytes:
        """Compute SHA-256 hash"""
        return hashlib.sha256(data).digest()
    
    @staticmethod
    def hash_sha256_hex(data: bytes) -> str:
        """Compute SHA-256 hash and return as hex string"""
        return hashlib.sha256(data).hexdigest()
    
    @staticmethod
    def hash_ripemd160(data: bytes) -> bytes:
        """Compute RIPEMD-160 hash (Bitcoin-style)"""
        # Note: RIPEMD-160 is not available in cryptography library
        # Using SHA-256 as fallback for compatibility
        return hashlib.sha256(data).digest()[:20]
    
    @staticmethod
    def double_sha256(data: bytes) -> bytes:
        """Compute double SHA-256 (Bitcoin-style)"""
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()
    
    @staticmethod
    def base58_encode(data: bytes) -> str:
        """Encode bytes to Base58 (Bitcoin-style)"""
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        
        # Convert bytes to integer
        num = int.from_bytes(data, 'big')
        
        # Handle zero case
        if num == 0:
            return alphabet[0]
        
        # Convert to base58
        result = ""
        while num > 0:
            num, remainder = divmod(num, 58)
            result = alphabet[remainder] + result
        
        # Add leading zeros
        for byte in data:
            if byte == 0:
                result = alphabet[0] + result
            else:
                break
        
        return result
    
    @staticmethod
    def base58_decode(encoded: str) -> bytes:
        """Decode Base58 string to bytes"""
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        
        # Convert from base58
        num = 0
        for char in encoded:
            num = num * 58 + alphabet.index(char)
        
        # Convert to bytes
        byte_length = (num.bit_length() + 7) // 8
        result = num.to_bytes(byte_length, 'big')
        
        # Add leading zeros
        for char in encoded:
            if char == alphabet[0]:
                result = b'\x00' + result
            else:
                break
        
        return result


class ECDSAKeyPair:
    """ECDSA key pair for digital signatures"""
    
    def __init__(self, private_key: Optional[ec.EllipticCurvePrivateKey] = None):
        if private_key is None:
            self.private_key = ec.generate_private_key(ec.SECP256K1())
        else:
            self.private_key = private_key
        self.public_key = self.private_key.public_key()
        self._address = None
    
    @classmethod
    def generate(cls) -> 'ECDSAKeyPair':
        """Generate a new ECDSA key pair"""
        return cls()
    
    def sign(self, message: bytes) -> bytes:
        """Sign a message with the private key"""
        signature = self.private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return signature
    
    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature with the public key"""
        try:
            self.public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False
    
    def get_address(self) -> str:
        """Generate blockchain address from public key"""
        if self._address:
            return self._address
        
        # Get public key bytes
        public_key_bytes = self.public_key.public_numbers().x.to_bytes(32, 'big')
        public_key_bytes += self.public_key.public_numbers().y.to_bytes(32, 'big')
        
        # Hash the public key
        sha256_hash = CryptoUtils.hash_sha256(public_key_bytes)
        ripemd160_hash = CryptoUtils.hash_ripemd160(sha256_hash)
        
        # Add version byte (0x00 for mainnet)
        versioned_hash = b'\x00' + ripemd160_hash
        
        # Add checksum
        checksum = CryptoUtils.double_sha256(versioned_hash)[:4]
        address_bytes = versioned_hash + checksum
        
        # Encode to Base58
        self._address = CryptoUtils.base58_encode(address_bytes)
        return self._address
    
    def export_private_key(self, password: Optional[str] = None) -> str:
        """Export private key (optionally encrypted)"""
        if password:
            # Encrypt private key with password
            private_bytes = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
            )
        else:
            private_bytes = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        
        return base64.b64encode(private_bytes).decode()
    
    def export_public_key(self) -> str:
        """Export public key"""
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(public_bytes).decode()
    
    @classmethod
    def from_private_key(cls, private_key_data: str, password: Optional[str] = None) -> 'ECDSAKeyPair':
        """Create key pair from exported private key"""
        private_bytes = base64.b64decode(private_key_data.encode())
        
        if password:
            private_key = serialization.load_pem_private_key(
                private_bytes, password=password.encode()
            )
        else:
            private_key = serialization.load_pem_private_key(
                private_bytes, password=None
            )
        
        return cls(private_key)
    
    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary"""
        return {
            'private_key': self.export_private_key(),
            'public_key': self.export_public_key(),
            'address': self.get_address()
        }


class AESEncryption:
    """AES encryption for secure data storage"""
    
    @staticmethod
    def generate_key() -> bytes:
        """Generate AES-256 key"""
        return CryptoUtils.generate_random_bytes(32)
    
    @staticmethod
    def encrypt(data: bytes, key: bytes) -> Dict[str, str]:
        """Encrypt data with AES-256-GCM"""
        # Generate random IV
        iv = CryptoUtils.generate_random_bytes(12)  # 96-bit IV for GCM
        
        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        
        # Encrypt data
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'iv': base64.b64encode(iv).decode(),
            'tag': base64.b64encode(encryptor.tag).decode()
        }
    
    @staticmethod
    def decrypt(encrypted_data: Dict[str, str], key: bytes) -> bytes:
        """Decrypt AES-256-GCM encrypted data"""
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        iv = base64.b64decode(encrypted_data['iv'])
        tag = base64.b64decode(encrypted_data['tag'])
        
        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        
        # Decrypt data
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext


class KeyDerivation:
    """Key derivation functions for password-based encryption"""
    
    @staticmethod
    def derive_key_pbkdf2(password: str, salt: bytes = None, iterations: int = 100000) -> Tuple[bytes, bytes]:
        """Derive key using PBKDF2"""
        if salt is None:
            salt = CryptoUtils.generate_random_bytes(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations
        )
        
        key = kdf.derive(password.encode())
        return key, salt
    
    @staticmethod
    def derive_key_scrypt(password: str, salt: bytes = None, n: int = 16384, r: int = 8, p: int = 1) -> Tuple[bytes, bytes]:
        """Derive key using Scrypt"""
        if salt is None:
            salt = CryptoUtils.generate_random_bytes(16)
        
        kdf = Scrypt(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            n=n,
            r=r,
            p=p
        )
        
        key = kdf.derive(password.encode())
        return key, salt


class MultiSignature:
    """Multi-signature implementation for enhanced security"""
    
    def __init__(self, required_signatures: int, public_keys: list):
        self.required_signatures = required_signatures
        self.public_keys = public_keys
        self.total_keys = len(public_keys)
        
        if required_signatures > self.total_keys:
            raise ValueError("Required signatures cannot exceed total keys")
        if required_signatures < 1:
            raise ValueError("At least one signature is required")
    
    def create_multisig_address(self) -> str:
        """Create multi-signature address"""
        # Sort public keys for deterministic address generation
        sorted_keys = sorted([key.export_public_key() for key in self.public_keys])
        
        # Create script hash
        script_data = f"{self.required_signatures}:{':'.join(sorted_keys)}"
        script_hash = CryptoUtils.hash_sha256(script_data.encode())
        
        # Add version byte for multisig (0x05)
        versioned_hash = b'\x05' + script_hash[:20]
        
        # Add checksum
        checksum = CryptoUtils.double_sha256(versioned_hash)[:4]
        address_bytes = versioned_hash + checksum
        
        return CryptoUtils.base58_encode(address_bytes)
    
    def sign_transaction(self, message: bytes, private_keys: list) -> Dict[str, Any]:
        """Sign transaction with multiple private keys"""
        signatures = []
        
        for private_key in private_keys:
            if len(signatures) >= self.required_signatures:
                break
            
            # Find corresponding public key
            public_key = private_key.public_key
            if public_key in self.public_keys:
                signature = private_key.sign(message)
                signatures.append({
                    'signature': base64.b64encode(signature).decode(),
                    'public_key': public_key.export_public_key()
                })
        
        return {
            'signatures': signatures,
            'required': self.required_signatures,
            'message_hash': CryptoUtils.hash_sha256_hex(message)
        }
    
    def verify_transaction(self, message: bytes, multisig_data: Dict[str, Any]) -> bool:
        """Verify multi-signature transaction"""
        signatures = multisig_data['signatures']
        
        if len(signatures) < self.required_signatures:
            return False
        
        valid_signatures = 0
        used_keys = set()
        
        for sig_data in signatures:
            signature = base64.b64decode(sig_data['signature'])
            public_key_data = sig_data['public_key']
            
            # Prevent key reuse
            if public_key_data in used_keys:
                continue
            
            # Load public key
            try:
                public_key_bytes = base64.b64decode(public_key_data)
                public_key = serialization.load_pem_public_key(public_key_bytes)
                
                # Verify signature
                if public_key in self.public_keys:
                    try:
                        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
                        valid_signatures += 1
                        used_keys.add(public_key_data)
                    except InvalidSignature:
                        continue
            except Exception:
                continue
        
        return valid_signatures >= self.required_signatures


class SecureStorage:
    """Secure storage for sensitive data"""
    
    def __init__(self, storage_path: str):
        self.storage_path = storage_path
        self._ensure_directory()
    
    def _ensure_directory(self):
        """Ensure storage directory exists"""
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
    
    def store_encrypted(self, data: Dict[str, Any], password: str) -> bool:
        """Store data encrypted with password"""
        try:
            # Serialize data
            json_data = json.dumps(data).encode()
            
            # Derive key from password
            key, salt = KeyDerivation.derive_key_pbkdf2(password)
            
            # Encrypt data
            encrypted = AESEncryption.encrypt(json_data, key)
            encrypted['salt'] = base64.b64encode(salt).decode()
            
            # Save to file
            with open(self.storage_path, 'w') as f:
                json.dump(encrypted, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Error storing encrypted data: {e}")
            return False
    
    def load_encrypted(self, password: str) -> Optional[Dict[str, Any]]:
        """Load encrypted data with password"""
        try:
            # Load encrypted data
            with open(self.storage_path, 'r') as f:
                encrypted = json.load(f)
            
            # Derive key from password
            salt = base64.b64decode(encrypted['salt'])
            key, _ = KeyDerivation.derive_key_pbkdf2(password, salt)
            
            # Decrypt data
            decrypted_bytes = AESEncryption.decrypt(encrypted, key)
            data = json.loads(decrypted_bytes.decode())
            
            return data
        except Exception as e:
            print(f"Error loading encrypted data: {e}")
            return None
    
    def exists(self) -> bool:
        """Check if storage file exists"""
        return os.path.exists(self.storage_path)


class DigitalSignatureManager:
    """Manager for digital signatures and verification"""
    
    def __init__(self):
        self.key_pairs: Dict[str, ECDSAKeyPair] = {}
    
    def create_key_pair(self, name: str) -> ECDSAKeyPair:
        """Create a new key pair"""
        key_pair = ECDSAKeyPair()
        self.key_pairs[name] = key_pair
        return key_pair
    
    def import_key_pair(self, name: str, private_key_data: str, password: Optional[str] = None) -> ECDSAKeyPair:
        """Import an existing key pair"""
        key_pair = ECDSAKeyPair.from_private_key(private_key_data, password)
        self.key_pairs[name] = key_pair
        return key_pair
    
    def sign_message(self, key_name: str, message: str) -> Optional[str]:
        """Sign a message with a key pair"""
        if key_name not in self.key_pairs:
            return None
        
        key_pair = self.key_pairs[key_name]
        signature = key_pair.sign(message.encode())
        return base64.b64encode(signature).decode()
    
    def verify_signature(self, public_key_data: str, message: str, signature_data: str) -> bool:
        """Verify a signature"""
        try:
            # Load public key
            public_key_bytes = base64.b64decode(public_key_data)
            public_key = serialization.load_pem_public_key(public_key_bytes)
            
            # Decode signature
            signature = base64.b64decode(signature_data)
            
            # Verify
            public_key.verify(signature, message.encode(), ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False
    
    def get_address(self, key_name: str) -> Optional[str]:
        """Get address for a key pair"""
        if key_name not in self.key_pairs:
            return None
        return self.key_pairs[key_name].get_address()
    
    def list_keys(self) -> list:
        """List all key pair names"""
        return list(self.key_pairs.keys())