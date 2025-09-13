"""Blockchain Module

This module provides the core blockchain functionality including:
- Transaction management
- Block creation and validation
- Blockchain data structure
- Consensus mechanisms
- Network protocols

Components:
- Transaction: Individual transaction handling
- Block: Block structure and validation
- Blockchain: Main blockchain data structure
- Consensus: Proof of Stake consensus mechanism
- Network: P2P networking (future implementation)
"""

# Import core blockchain components
from .core.transaction import Transaction
from .core.block import Block
from .core.blockchain import Blockchain

# Import consensus mechanisms
from .consensus.pos import ProofOfStakeConsensus

__all__ = [
    'Transaction',
    'Block', 
    'Blockchain',
    'ProofOfStakeConsensus',
    'create_blockchain_system',
    'validate_transaction',
    'calculate_merkle_root'
]

__version__ = '1.0.0'
__author__ = 'Smart Contract Platform Team'

# Configuration constants
DEFAULT_DIFFICULTY = 4
BLOCK_TIME = 12  # seconds
MAX_BLOCK_SIZE = 1024 * 1024  # 1MB
MAX_TRANSACTIONS_PER_BLOCK = 1000

def create_blockchain_system(consensus=None, difficulty=DEFAULT_DIFFICULTY):
    """Create a complete blockchain system
    
    Args:
        consensus: Consensus mechanism (defaults to PoS)
        difficulty: Mining difficulty
    
    Returns:
        Blockchain: Configured blockchain instance
    """
    if consensus is None:
        consensus = ProofOfStakeConsensus()
    
    blockchain = Blockchain(initial_difficulty=difficulty)
    blockchain.consensus = consensus
    
    return blockchain

def validate_transaction(transaction):
    """Validate a transaction
    
    Args:
        transaction (Transaction): Transaction to validate
    
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        return transaction.is_valid()
    except Exception:
        return False

def calculate_merkle_root(transactions):
    """Calculate merkle root for a list of transactions
    
    Args:
        transactions (list): List of transactions
    
    Returns:
        str: Merkle root hash
    """
    if not transactions:
        return "0" * 64
    
    import hashlib
    
    # Convert transactions to hashes
    tx_hashes = []
    for tx in transactions:
        if hasattr(tx, 'hash'):
            tx_hashes.append(tx.hash)
        else:
            tx_hashes.append(str(tx))
    
    # Build merkle tree
    while len(tx_hashes) > 1:
        next_level = []
        
        # Process pairs
        for i in range(0, len(tx_hashes), 2):
            left = tx_hashes[i]
            right = tx_hashes[i + 1] if i + 1 < len(tx_hashes) else left
            
            combined = left + right
            hash_result = hashlib.sha256(combined.encode()).hexdigest()
            next_level.append(hash_result)
        
        tx_hashes = next_level
    
    return tx_hashes[0] if tx_hashes else "0" * 64

# Global blockchain instance (singleton)
_blockchain_instance = None

def get_blockchain_instance():
    """Get the global blockchain instance
    
    Returns:
        Blockchain: Global blockchain instance
    """
    global _blockchain_instance
    if _blockchain_instance is None:
        _blockchain_instance = create_blockchain_system()
    return _blockchain_instance

def reset_blockchain_instance():
    """Reset the global blockchain instance"""
    global _blockchain_instance
    _blockchain_instance = None

# Network configuration
NETWORK_CONFIG = {
    'default_port': 8333,
    'max_peers': 50,
    'connection_timeout': 30,
    'sync_interval': 60
}

# Export configuration
CONFIG = {
    'DEFAULT_DIFFICULTY': DEFAULT_DIFFICULTY,
    'BLOCK_TIME': BLOCK_TIME,
    'MAX_BLOCK_SIZE': MAX_BLOCK_SIZE,
    'MAX_TRANSACTIONS_PER_BLOCK': MAX_TRANSACTIONS_PER_BLOCK,
    'NETWORK_CONFIG': NETWORK_CONFIG
}

print(f"Blockchain module loaded - Version {__version__}")
print(f"Default difficulty: {DEFAULT_DIFFICULTY}, Block time: {BLOCK_TIME}s")