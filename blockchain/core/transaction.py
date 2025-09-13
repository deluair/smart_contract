import hashlib
import json
import time
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature


@dataclass
class TransactionInput:
    """Represents an input to a transaction (UTXO reference)"""
    tx_id: str  # Transaction ID being spent
    output_index: int  # Index of the output being spent
    signature: Optional[str] = None  # Digital signature
    public_key: Optional[str] = None  # Public key for verification


@dataclass
class TransactionOutput:
    """Represents an output of a transaction"""
    amount: float  # Amount being transferred
    recipient: str  # Recipient's address
    asset_type: str = "COIN"  # Type of asset (COIN, TOKEN, etc.)
    contract_data: Optional[Dict[str, Any]] = None  # Smart contract data


class Transaction:
    """Core transaction class for the blockchain"""
    
    def __init__(self, 
                 sender: str,
                 inputs: List[TransactionInput] = None,
                 outputs: List[TransactionOutput] = None,
                 tx_type: str = "TRANSFER",
                 data: Optional[Dict[str, Any]] = None,
                 gas_limit: int = 21000,
                 gas_price: float = 0.001):
        """
        Initialize a new transaction
        
        Args:
            sender: Address of the transaction sender
            inputs: List of transaction inputs (UTXOs being spent)
            outputs: List of transaction outputs (new UTXOs being created)
            tx_type: Type of transaction (TRANSFER, CONTRACT_DEPLOY, CONTRACT_CALL)
            data: Additional transaction data (smart contract code, function calls)
            gas_limit: Maximum gas units for execution
            gas_price: Price per gas unit
        """
        self.sender = sender
        self.inputs = inputs or []
        self.outputs = outputs or []
        self.tx_type = tx_type
        self.data = data or {}
        self.gas_limit = gas_limit
        self.gas_price = gas_price
        self.timestamp = time.time()
        self.nonce = 0
        self.tx_id = None
        self.signature = None
        self.is_valid = False
        
    def calculate_hash(self) -> str:
        """Calculate the hash of the transaction"""
        tx_data = {
            'sender': self.sender,
            'inputs': [asdict(inp) for inp in self.inputs],
            'outputs': [asdict(out) for out in self.outputs],
            'tx_type': self.tx_type,
            'data': self.data,
            'gas_limit': self.gas_limit,
            'gas_price': self.gas_price,
            'timestamp': self.timestamp,
            'nonce': self.nonce
        }
        
        tx_string = json.dumps(tx_data, sort_keys=True)
        return hashlib.sha256(tx_string.encode()).hexdigest()
    
    def set_transaction_id(self):
        """Set the transaction ID based on the hash"""
        self.tx_id = self.calculate_hash()
    
    def calculate_fee(self) -> float:
        """Calculate the transaction fee"""
        base_fee = len(self.inputs) * 0.0001 + len(self.outputs) * 0.0001
        gas_fee = self.gas_limit * self.gas_price
        return base_fee + gas_fee
    
    def get_total_input_amount(self) -> float:
        """Calculate total input amount (requires UTXO lookup)"""
        # This would typically require looking up UTXO values
        # For now, return 0 as placeholder
        return 0.0
    
    def get_total_output_amount(self) -> float:
        """Calculate total output amount"""
        return sum(output.amount for output in self.outputs)
    
    def sign_transaction(self, private_key: ec.EllipticCurvePrivateKey):
        """Sign the transaction with a private key"""
        if self.tx_id is None:
            self.set_transaction_id()
            
        message = self.tx_id.encode()
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        self.signature = signature.hex()
    
    def verify_signature(self, public_key: ec.EllipticCurvePublicKey) -> bool:
        """Verify the transaction signature"""
        if not self.signature or not self.tx_id:
            return False
            
        try:
            signature_bytes = bytes.fromhex(self.signature)
            message = self.tx_id.encode()
            public_key.verify(signature_bytes, message, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError):
            return False
    
    def validate_transaction(self, utxo_set: Dict[str, Dict]) -> bool:
        """Validate the transaction against UTXO set"""
        # Check if transaction is already validated
        if self.is_valid:
            return True
            
        # Basic validation checks
        if not self.tx_id:
            self.set_transaction_id()
            
        # Check if outputs are positive
        for output in self.outputs:
            if output.amount <= 0:
                return False
                
        # For coinbase transactions (mining rewards)
        if self.tx_type == "COINBASE":
            if len(self.inputs) != 0:
                return False
            self.is_valid = True
            return True
            
        # Validate inputs exist in UTXO set
        total_input_value = 0
        for tx_input in self.inputs:
            utxo_key = f"{tx_input.tx_id}:{tx_input.output_index}"
            if utxo_key not in utxo_set:
                return False
            total_input_value += utxo_set[utxo_key]['amount']
            
        # Check if input value >= output value + fees
        total_output_value = self.get_total_output_amount()
        transaction_fee = self.calculate_fee()
        
        if total_input_value < total_output_value + transaction_fee:
            return False
            
        self.is_valid = True
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert transaction to dictionary"""
        return {
            'tx_id': self.tx_id,
            'sender': self.sender,
            'inputs': [asdict(inp) for inp in self.inputs],
            'outputs': [asdict(out) for out in self.outputs],
            'tx_type': self.tx_type,
            'data': self.data,
            'gas_limit': self.gas_limit,
            'gas_price': self.gas_price,
            'timestamp': self.timestamp,
            'nonce': self.nonce,
            'signature': self.signature,
            'is_valid': self.is_valid
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Transaction':
        """Create transaction from dictionary"""
        tx = cls(
            sender=data['sender'],
            tx_type=data.get('tx_type', 'TRANSFER'),
            data=data.get('data', {}),
            gas_limit=data.get('gas_limit', 21000),
            gas_price=data.get('gas_price', 0.001)
        )
        
        # Reconstruct inputs and outputs
        tx.inputs = [TransactionInput(**inp) for inp in data.get('inputs', [])]
        tx.outputs = [TransactionOutput(**out) for out in data.get('outputs', [])]
        
        # Set other properties
        tx.tx_id = data.get('tx_id')
        tx.timestamp = data.get('timestamp', time.time())
        tx.nonce = data.get('nonce', 0)
        tx.signature = data.get('signature')
        tx.is_valid = data.get('is_valid', False)
        
        return tx
    
    def __str__(self) -> str:
        return f"Transaction(id={self.tx_id[:8]}..., type={self.tx_type}, sender={self.sender[:8]}...)"
    
    def __repr__(self) -> str:
        return self.__str__()


class TransactionPool:
    """Pool of unconfirmed transactions"""
    
    def __init__(self):
        self.pending_transactions: Dict[str, Transaction] = {}
        self.max_pool_size = 10000
    
    def add_transaction(self, transaction: Transaction) -> bool:
        """Add a transaction to the pool"""
        if len(self.pending_transactions) >= self.max_pool_size:
            return False
            
        if not transaction.tx_id:
            transaction.set_transaction_id()
            
        if transaction.tx_id in self.pending_transactions:
            return False
            
        self.pending_transactions[transaction.tx_id] = transaction
        return True
    
    def remove_transaction(self, tx_id: str) -> bool:
        """Remove a transaction from the pool"""
        if tx_id in self.pending_transactions:
            del self.pending_transactions[tx_id]
            return True
        return False
    
    def get_transactions_for_block(self, max_transactions: int = 100) -> List[Transaction]:
        """Get transactions for inclusion in a new block"""
        # Sort by gas price (highest first) for fee prioritization
        sorted_txs = sorted(
            self.pending_transactions.values(),
            key=lambda tx: tx.gas_price,
            reverse=True
        )
        return sorted_txs[:max_transactions]
    
    def clear_transactions(self, tx_ids: List[str]):
        """Remove multiple transactions from the pool"""
        for tx_id in tx_ids:
            self.remove_transaction(tx_id)
    
    def get_pool_size(self) -> int:
        """Get the current pool size"""
        return len(self.pending_transactions)
    
    def get_transaction(self, tx_id: str) -> Optional[Transaction]:
        """Get a specific transaction from the pool"""
        return self.pending_transactions.get(tx_id)