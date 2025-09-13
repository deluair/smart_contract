from typing import Dict, List, Optional, Tuple, Union
import os
import json
import time
import hashlib
import hmac
from dataclasses import dataclass, field
from enum import Enum
from decimal import Decimal, getcontext
import secrets
from mnemonic import Mnemonic

from blockchain.core.transaction import Transaction, TransactionInput, TransactionOutput
from security.cryptography import ECDSAKeyPair, CryptoUtils
from security.signatures import SignatureData, TransactionSigner

# Set precision for financial calculations
getcontext().prec = 28

class WalletType(Enum):
    HD_WALLET = "HD_WALLET"  # Hierarchical Deterministic
    SIMPLE_WALLET = "SIMPLE_WALLET"
    MULTISIG_WALLET = "MULTISIG_WALLET"
    HARDWARE_WALLET = "HARDWARE_WALLET"

class AccountType(Enum):
    STANDARD = "STANDARD"
    SAVINGS = "SAVINGS"
    TRADING = "TRADING"
    STAKING = "STAKING"
    MULTISIG = "MULTISIG"

class TransactionStatus(Enum):
    PENDING = "PENDING"
    CONFIRMED = "CONFIRMED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

@dataclass
class HDKey:
    """Hierarchical Deterministic Key"""
    private_key: bytes
    public_key: bytes
    chain_code: bytes
    depth: int
    parent_fingerprint: bytes
    child_number: int
    
    def fingerprint(self) -> bytes:
        """Calculate key fingerprint"""
        return hashlib.sha256(self.public_key).digest()[:4]

@dataclass
class Account:
    """Wallet Account"""
    id: str
    name: str
    account_type: AccountType
    address: str
    public_key: str
    private_key: str  # Encrypted in storage
    derivation_path: str
    balance: Dict[str, int] = field(default_factory=dict)  # token -> amount
    nonce: int = 0
    created_at: int = field(default_factory=lambda: int(time.time()))
    
@dataclass
class WalletTransaction:
    """Wallet transaction record"""
    tx_hash: str
    from_address: str
    to_address: str
    amount: int
    token: str
    fee: int
    status: TransactionStatus
    timestamp: int
    block_height: int = 0
    confirmations: int = 0
    memo: str = ""

@dataclass
class MultiSigConfig:
    """Multi-signature configuration"""
    required_signatures: int
    total_signers: int
    signer_addresses: List[str]
    signer_public_keys: List[str]
    
    @property
    def is_valid(self) -> bool:
        return (1 <= self.required_signatures <= self.total_signers and
                len(self.signer_addresses) == self.total_signers and
                len(self.signer_public_keys) == self.total_signers)

class HDWallet:
    """Hierarchical Deterministic Wallet"""
    
    def __init__(self, mnemonic: Optional[str] = None, passphrase: str = ""):
        self.mnemonic_generator = Mnemonic("english")
        
        if mnemonic:
            if not self.mnemonic_generator.check(mnemonic):
                raise ValueError("Invalid mnemonic")
            self.mnemonic = mnemonic
        else:
            self.mnemonic = self.mnemonic_generator.generate(strength=256)
            
        self.passphrase = passphrase
        self.seed = self.mnemonic_generator.to_seed(self.mnemonic, passphrase)
        self.master_key = self._derive_master_key()
        
        # Derived keys cache
        self.derived_keys: Dict[str, HDKey] = {}
        
    def _derive_master_key(self) -> HDKey:
        """Derive master key from seed"""
        # HMAC-SHA512 with "Bitcoin seed" as key
        hmac_result = hmac.new(b"Bitcoin seed", self.seed, hashlib.sha512).digest()
        
        private_key = hmac_result[:32]
        chain_code = hmac_result[32:]
        
        # Generate public key from private key
        # Create ECDSAKeyPair from raw private key bytes
        from cryptography.hazmat.primitives.asymmetric import ec
        private_key_int = int.from_bytes(private_key, 'big')
        ec_private_key = ec.derive_private_key(private_key_int, ec.SECP256K1())
        key_pair = ECDSAKeyPair(ec_private_key)
        
        # Get public key bytes from the key pair
        public_key_bytes = key_pair.public_key.public_numbers().x.to_bytes(32, 'big')
        public_key_bytes += key_pair.public_key.public_numbers().y.to_bytes(32, 'big')
        
        return HDKey(
            private_key=private_key,
            public_key=public_key_bytes,
            chain_code=chain_code,
            depth=0,
            parent_fingerprint=b'\x00' * 4,
            child_number=0
        )
        
    def derive_key(self, path: str) -> HDKey:
        """Derive key from derivation path (e.g., "m/44'/0'/0'/0/0")"""
        if path in self.derived_keys:
            return self.derived_keys[path]
            
        # Parse derivation path
        if not path.startswith("m/"):
            raise ValueError("Invalid derivation path")
            
        path_elements = path[2:].split("/")
        current_key = self.master_key
        
        for element in path_elements:
            if element == "":
                continue
                
            # Check for hardened derivation
            hardened = element.endswith("'")
            if hardened:
                index = int(element[:-1]) + 0x80000000
            else:
                index = int(element)
                
            current_key = self._derive_child_key(current_key, index)
            
        self.derived_keys[path] = current_key
        return current_key
        
    def _derive_child_key(self, parent_key: HDKey, index: int) -> HDKey:
        """Derive child key from parent key"""
        if index >= 0x80000000:  # Hardened derivation
            # Use private key for hardened derivation
            data = b'\x00' + parent_key.private_key + index.to_bytes(4, 'big')
        else:  # Non-hardened derivation
            # Use public key for non-hardened derivation
            data = parent_key.public_key + index.to_bytes(4, 'big')
            
        hmac_result = hmac.new(parent_key.chain_code, data, hashlib.sha512).digest()
        
        child_private_key = hmac_result[:32]
        child_chain_code = hmac_result[32:]
        
        # Add parent private key to child private key (modulo curve order)
        # Simplified implementation - in production, use proper elliptic curve arithmetic
        combined_key = int.from_bytes(parent_key.private_key, 'big') + int.from_bytes(child_private_key, 'big')
        combined_key = combined_key % (2**256)  # Simplified modulo
        
        final_private_key = combined_key.to_bytes(32, 'big')
        
        # Generate public key
        from cryptography.hazmat.primitives.asymmetric import ec
        private_key_int = int.from_bytes(final_private_key, 'big')
        ec_private_key = ec.derive_private_key(private_key_int, ec.SECP256K1())
        key_pair = ECDSAKeyPair(ec_private_key)
        
        # Get public key bytes
        public_key_bytes = key_pair.public_key.public_numbers().x.to_bytes(32, 'big')
        public_key_bytes += key_pair.public_key.public_numbers().y.to_bytes(32, 'big')
        
        return HDKey(
            private_key=final_private_key,
            public_key=public_key_bytes,
            chain_code=child_chain_code,
            depth=parent_key.depth + 1,
            parent_fingerprint=parent_key.fingerprint(),
            child_number=index
        )

class Wallet:
    """Main Wallet Class"""
    
    def __init__(self, wallet_id: str, wallet_type: WalletType = WalletType.HD_WALLET):
        self.wallet_id = wallet_id
        self.wallet_type = wallet_type
        self.created_at = int(time.time())
        
        # Core components
        self.accounts: Dict[str, Account] = {}
        self.hd_wallet: Optional[HDWallet] = None
        self.multisig_configs: Dict[str, MultiSigConfig] = {}
        
        # Transaction management
        self.transactions: Dict[str, WalletTransaction] = {}
        self.pending_transactions: Dict[str, Transaction] = {}
        
        # Security
        self.crypto_utils = CryptoUtils()
        self.transaction_signer = TransactionSigner()
        
        # Address book
        self.address_book: Dict[str, str] = {}  # address -> name
        
        # Settings
        self.default_fee_rate = 1000  # Default fee rate in satoshis per byte
        self.auto_confirm_threshold = 6  # Confirmations needed for auto-confirm
        
    def initialize_hd_wallet(self, mnemonic: Optional[str] = None, passphrase: str = "") -> str:
        """Initialize HD wallet"""
        if self.wallet_type != WalletType.HD_WALLET:
            raise ValueError("Wallet type must be HD_WALLET")
            
        self.hd_wallet = HDWallet(mnemonic, passphrase)
        return self.hd_wallet.mnemonic
        
    def create_account(self, name: str, account_type: AccountType = AccountType.STANDARD, 
                      derivation_path: Optional[str] = None) -> str:
        """Create a new account"""
        account_id = f"account_{len(self.accounts)}_{int(time.time())}"
        
        if self.wallet_type == WalletType.HD_WALLET:
            if not self.hd_wallet:
                raise ValueError("HD wallet not initialized")
                
            if not derivation_path:
                # Standard BIP44 path: m/44'/0'/account'/0/0
                account_index = len(self.accounts)
                derivation_path = f"m/44'/0'/{account_index}'/0/0"
                
            hd_key = self.hd_wallet.derive_key(derivation_path)
            # Create key pair from HD key
            from cryptography.hazmat.primitives.asymmetric import ec
            private_key_int = int.from_bytes(hd_key.private_key, 'big')
            ec_private_key = ec.derive_private_key(private_key_int, ec.SECP256K1())
            key_pair = ECDSAKeyPair(ec_private_key)
            
        else:
            # Generate new key pair for simple wallet
            key_pair = ECDSAKeyPair.generate()
            derivation_path = ""
            
        # Create account
        account = Account(
            id=account_id,
            name=name,
            account_type=account_type,
            address=key_pair.get_address(),
            public_key=key_pair.export_public_key(),
            private_key=key_pair.export_private_key(),  # Should be encrypted in production
            derivation_path=derivation_path
        )
        
        self.accounts[account_id] = account
        return account_id
        
    def create_multisig_account(self, name: str, required_signatures: int, 
                               signer_public_keys: List[str]) -> str:
        """Create a multi-signature account"""
        if len(signer_public_keys) < required_signatures:
            raise ValueError("Not enough signers for required signatures")
            
        # Generate multisig address
        multisig_script = self._create_multisig_script(required_signatures, signer_public_keys)
        multisig_address = self._script_to_address(multisig_script)
        
        # Create multisig config
        config = MultiSigConfig(
            required_signatures=required_signatures,
            total_signers=len(signer_public_keys),
            signer_addresses=[self._pubkey_to_address(pk) for pk in signer_public_keys],
            signer_public_keys=signer_public_keys
        )
        
        account_id = f"multisig_{len(self.accounts)}_{int(time.time())}"
        
        # Create account
        account = Account(
            id=account_id,
            name=name,
            account_type=AccountType.MULTISIG,
            address=multisig_address,
            public_key="",  # Not applicable for multisig
            private_key="",  # Not applicable for multisig
            derivation_path=""
        )
        
        self.accounts[account_id] = account
        self.multisig_configs[account_id] = config
        
        return account_id
        
    def get_account_balance(self, account_id: str, token: str = "native") -> int:
        """Get account balance for a specific token"""
        if account_id not in self.accounts:
            return 0
            
        account = self.accounts[account_id]
        return account.balance.get(token, 0)
        
    def update_account_balance(self, account_id: str, token: str, amount: int):
        """Update account balance"""
        if account_id not in self.accounts:
            return
            
        account = self.accounts[account_id]
        account.balance[token] = account.balance.get(token, 0) + amount
        
    def create_transaction(self, from_account_id: str, to_address: str, 
                          amount: int, token: str = "native", 
                          fee: Optional[int] = None, memo: str = "") -> str:
        """Create a new transaction"""
        if from_account_id not in self.accounts:
            raise ValueError("Account not found")
            
        from_account = self.accounts[from_account_id]
        
        # Check balance
        available_balance = self.get_account_balance(from_account_id, token)
        if fee is None:
            fee = self.default_fee_rate
            
        total_needed = amount + (fee if token == "native" else 0)
        if available_balance < total_needed:
            raise ValueError("Insufficient balance")
            
        # Create transaction inputs
        tx_input = TransactionInput(
            previous_tx_hash="",  # Would be filled from UTXO set
            output_index=0,
            script_sig="",
            sequence=0xffffffff
        )
        
        # Create transaction outputs
        tx_outputs = [
            TransactionOutput(
                amount=amount,
                script_pubkey=to_address,
                recipient=to_address
            )
        ]
        
        # Add change output if needed
        change_amount = available_balance - total_needed
        if change_amount > 0:
            tx_outputs.append(
                TransactionOutput(
                    amount=change_amount,
                    script_pubkey=from_account.address,
                    recipient=from_account.address
                )
            )
            
        # Create transaction
        transaction = Transaction(
            inputs=[tx_input],
            outputs=tx_outputs,
            timestamp=int(time.time()),
            fee=fee,
            sender=from_account.address
        )
        
        # Sign transaction
        if from_account.account_type == AccountType.MULTISIG:
            # For multisig, return unsigned transaction
            self.pending_transactions[transaction.hash] = transaction
        else:
            # Sign with account private key
            private_key = from_account.private_key  # Should decrypt in production
            signature = self.transaction_signer.sign_transaction(transaction, private_key)
            transaction.signature = signature.signature
            
        # Record transaction
        wallet_tx = WalletTransaction(
            tx_hash=transaction.hash,
            from_address=from_account.address,
            to_address=to_address,
            amount=amount,
            token=token,
            fee=fee,
            status=TransactionStatus.PENDING,
            timestamp=transaction.timestamp,
            memo=memo
        )
        
        self.transactions[transaction.hash] = wallet_tx
        
        # Update account nonce
        from_account.nonce += 1
        
        return transaction.hash
        
    def sign_multisig_transaction(self, tx_hash: str, signer_private_key: str) -> bool:
        """Sign a multisig transaction"""
        if tx_hash not in self.pending_transactions:
            return False
            
        transaction = self.pending_transactions[tx_hash]
        
        # Find the multisig account
        multisig_account = None
        for account in self.accounts.values():
            if account.address == transaction.sender and account.account_type == AccountType.MULTISIG:
                multisig_account = account
                break
                
        if not multisig_account or multisig_account.id not in self.multisig_configs:
            return False
            
        config = self.multisig_configs[multisig_account.id]
        
        # Sign transaction
        signature = self.transaction_signer.sign_transaction(transaction, signer_private_key)
        
        # Add signature to transaction (simplified - would need proper multisig handling)
        if not hasattr(transaction, 'signatures'):
            transaction.signatures = []
        transaction.signatures.append(signature.signature)
        
        # Check if we have enough signatures
        if len(transaction.signatures) >= config.required_signatures:
            # Transaction is fully signed
            transaction.signature = "multisig_" + "_".join(transaction.signatures)
            del self.pending_transactions[tx_hash]
            
        return True
        
    def import_private_key(self, private_key: str, name: str) -> str:
        """Import account from private key"""
        try:
            key_pair = ECDSAKeyPair.from_private_key(bytes.fromhex(private_key))
            
            account_id = f"imported_{len(self.accounts)}_{int(time.time())}"
            
            account = Account(
                id=account_id,
                name=name,
                account_type=AccountType.STANDARD,
                address=key_pair.address,
                public_key=key_pair.public_key_hex,
                private_key=private_key,
                derivation_path="imported"
            )
            
            self.accounts[account_id] = account
            return account_id
            
        except Exception:
            raise ValueError("Invalid private key")
            
    def export_private_key(self, account_id: str) -> str:
        """Export account private key"""
        if account_id not in self.accounts:
            raise ValueError("Account not found")
            
        account = self.accounts[account_id]
        if account.account_type == AccountType.MULTISIG:
            raise ValueError("Cannot export private key for multisig account")
            
        return account.private_key
        
    def add_address_to_book(self, address: str, name: str):
        """Add address to address book"""
        self.address_book[address] = name
        
    def get_transaction_history(self, account_id: Optional[str] = None, 
                               limit: int = 100) -> List[WalletTransaction]:
        """Get transaction history"""
        transactions = list(self.transactions.values())
        
        if account_id and account_id in self.accounts:
            account = self.accounts[account_id]
            transactions = [
                tx for tx in transactions 
                if tx.from_address == account.address or tx.to_address == account.address
            ]
            
        # Sort by timestamp (newest first)
        transactions.sort(key=lambda x: x.timestamp, reverse=True)
        
        return transactions[:limit]
        
    def update_transaction_status(self, tx_hash: str, status: TransactionStatus, 
                                 block_height: int = 0, confirmations: int = 0):
        """Update transaction status"""
        if tx_hash in self.transactions:
            tx = self.transactions[tx_hash]
            tx.status = status
            tx.block_height = block_height
            tx.confirmations = confirmations
            
    def _create_multisig_script(self, required: int, public_keys: List[str]) -> str:
        """Create multisig script"""
        # Simplified multisig script creation
        script = f"{required}"
        for pk in sorted(public_keys):  # Sort for deterministic order
            script += f" {pk}"
        script += f" {len(public_keys)} CHECKMULTISIG"
        return script
        
    def _script_to_address(self, script: str) -> str:
        """Convert script to address"""
        # Simplified script to address conversion
        script_hash = hashlib.sha256(script.encode()).hexdigest()
        return f"3{script_hash[:32]}"  # P2SH address format
        
    def _pubkey_to_address(self, public_key: str) -> str:
        """Convert public key to address"""
        # Simplified public key to address conversion
        # Handle both hex and base64 encoded public keys
        try:
            # Try hex first
            pubkey_bytes = bytes.fromhex(public_key)
        except ValueError:
            # If not hex, assume base64
            import base64
            pubkey_bytes = base64.b64decode(public_key)
        
        pubkey_hash = hashlib.sha256(pubkey_bytes).hexdigest()
        return f"1{pubkey_hash[:32]}"  # P2PKH address format
        
    def get_wallet_info(self) -> Dict[str, any]:
        """Get comprehensive wallet information"""
        total_accounts = len(self.accounts)
        total_balance = {}
        
        # Calculate total balances across all accounts
        for account in self.accounts.values():
            for token, amount in account.balance.items():
                total_balance[token] = total_balance.get(token, 0) + amount
                
        return {
            'wallet_id': self.wallet_id,
            'wallet_type': self.wallet_type.value,
            'created_at': self.created_at,
            'total_accounts': total_accounts,
            'total_balance': total_balance,
            'total_transactions': len(self.transactions),
            'pending_transactions': len(self.pending_transactions),
            'address_book_entries': len(self.address_book),
            'has_hd_wallet': self.hd_wallet is not None,
            'multisig_accounts': len(self.multisig_configs)
        }
        
    def get_account_info(self, account_id: str) -> Optional[Dict[str, any]]:
        """Get detailed account information"""
        if account_id not in self.accounts:
            return None
            
        account = self.accounts[account_id]
        
        info = {
            'id': account.id,
            'name': account.name,
            'type': account.account_type.value,
            'address': account.address,
            'public_key': account.public_key,
            'derivation_path': account.derivation_path,
            'balance': dict(account.balance),
            'nonce': account.nonce,
            'created_at': account.created_at
        }
        
        # Add multisig info if applicable
        if account.account_type == AccountType.MULTISIG and account_id in self.multisig_configs:
            config = self.multisig_configs[account_id]
            info['multisig_config'] = {
                'required_signatures': config.required_signatures,
                'total_signers': config.total_signers,
                'signer_addresses': config.signer_addresses
            }
            
        return info
        
    def backup_wallet(self) -> Dict[str, any]:
        """Create wallet backup data"""
        backup_data = {
            'wallet_id': self.wallet_id,
            'wallet_type': self.wallet_type.value,
            'created_at': self.created_at,
            'accounts': {},
            'multisig_configs': {},
            'address_book': dict(self.address_book)
        }
        
        # Backup accounts (private keys should be encrypted)
        for account_id, account in self.accounts.items():
            backup_data['accounts'][account_id] = {
                'id': account.id,
                'name': account.name,
                'account_type': account.account_type.value,
                'address': account.address,
                'public_key': account.public_key,
                'private_key': account.private_key,  # Should be encrypted
                'derivation_path': account.derivation_path,
                'created_at': account.created_at
            }
            
        # Backup multisig configs
        for config_id, config in self.multisig_configs.items():
            backup_data['multisig_configs'][config_id] = {
                'required_signatures': config.required_signatures,
                'total_signers': config.total_signers,
                'signer_addresses': config.signer_addresses,
                'signer_public_keys': config.signer_public_keys
            }
            
        # Backup HD wallet mnemonic (should be encrypted)
        if self.hd_wallet:
            backup_data['hd_mnemonic'] = self.hd_wallet.mnemonic
            
        return backup_data
        
    def restore_from_backup(self, backup_data: Dict[str, any]) -> bool:
        """Restore wallet from backup data"""
        try:
            self.wallet_id = backup_data['wallet_id']
            self.wallet_type = WalletType(backup_data['wallet_type'])
            self.created_at = backup_data['created_at']
            
            # Restore accounts
            self.accounts = {}
            for account_id, account_data in backup_data.get('accounts', {}).items():
                account = Account(
                    id=account_data['id'],
                    name=account_data['name'],
                    account_type=AccountType(account_data['account_type']),
                    address=account_data['address'],
                    public_key=account_data['public_key'],
                    private_key=account_data['private_key'],
                    derivation_path=account_data['derivation_path'],
                    created_at=account_data['created_at']
                )
                self.accounts[account_id] = account
                
            # Restore multisig configs
            self.multisig_configs = {}
            for config_id, config_data in backup_data.get('multisig_configs', {}).items():
                config = MultiSigConfig(
                    required_signatures=config_data['required_signatures'],
                    total_signers=config_data['total_signers'],
                    signer_addresses=config_data['signer_addresses'],
                    signer_public_keys=config_data['signer_public_keys']
                )
                self.multisig_configs[config_id] = config
                
            # Restore address book
            self.address_book = backup_data.get('address_book', {})
            
            # Restore HD wallet if present
            if 'hd_mnemonic' in backup_data:
                self.hd_wallet = HDWallet(backup_data['hd_mnemonic'])
                
            return True
            
        except Exception:
            return False