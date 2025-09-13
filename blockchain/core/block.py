import hashlib
import json
import time
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from .transaction import Transaction


@dataclass
class MerkleNode:
    """Node in a Merkle tree"""
    hash_value: str
    left: Optional['MerkleNode'] = None
    right: Optional['MerkleNode'] = None
    is_leaf: bool = False


class MerkleTree:
    """Merkle tree implementation for efficient transaction verification"""
    
    def __init__(self, transactions: List[Transaction]):
        self.transactions = transactions
        self.root = self._build_tree()
    
    def _build_tree(self) -> Optional[MerkleNode]:
        """Build the Merkle tree from transactions"""
        if not self.transactions:
            return None
            
        # Create leaf nodes from transaction hashes
        leaves = []
        for tx in self.transactions:
            if not tx.tx_id:
                tx.set_transaction_id()
            node = MerkleNode(hash_value=tx.tx_id, is_leaf=True)
            leaves.append(node)
        
        # If odd number of transactions, duplicate the last one
        if len(leaves) % 2 == 1:
            leaves.append(leaves[-1])
        
        return self._build_tree_recursive(leaves)
    
    def _build_tree_recursive(self, nodes: List[MerkleNode]) -> MerkleNode:
        """Recursively build the Merkle tree"""
        if len(nodes) == 1:
            return nodes[0]
        
        next_level = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i + 1] if i + 1 < len(nodes) else nodes[i]
            
            combined_hash = hashlib.sha256(
                (left.hash_value + right.hash_value).encode()
            ).hexdigest()
            
            parent = MerkleNode(
                hash_value=combined_hash,
                left=left,
                right=right
            )
            next_level.append(parent)
        
        # If odd number of nodes, duplicate the last one
        if len(next_level) % 2 == 1 and len(next_level) > 1:
            next_level.append(next_level[-1])
        
        return self._build_tree_recursive(next_level)
    
    def get_root_hash(self) -> str:
        """Get the root hash of the Merkle tree"""
        return self.root.hash_value if self.root else ""
    
    def get_proof(self, tx_index: int) -> List[Dict[str, Any]]:
        """Get Merkle proof for a transaction at given index"""
        if tx_index >= len(self.transactions) or not self.root:
            return []
        
        proof = []
        self._get_proof_recursive(self.root, tx_index, len(self.transactions), proof)
        return proof
    
    def _get_proof_recursive(self, node: MerkleNode, target_index: int, 
                           total_leaves: int, proof: List[Dict[str, Any]], 
                           current_index: int = 0, current_range: int = None):
        """Recursively build Merkle proof"""
        if current_range is None:
            current_range = total_leaves
        
        if node.is_leaf:
            return
        
        mid = current_range // 2
        
        if target_index < current_index + mid:
            # Target is in left subtree, add right sibling to proof
            if node.right:
                proof.append({
                    'hash': node.right.hash_value,
                    'position': 'right'
                })
            if node.left:
                self._get_proof_recursive(
                    node.left, target_index, total_leaves, proof,
                    current_index, mid
                )
        else:
            # Target is in right subtree, add left sibling to proof
            if node.left:
                proof.append({
                    'hash': node.left.hash_value,
                    'position': 'left'
                })
            if node.right:
                self._get_proof_recursive(
                    node.right, target_index, total_leaves, proof,
                    current_index + mid, current_range - mid
                )


class BlockHeader:
    """Block header containing metadata"""
    
    def __init__(self, 
                 previous_hash: str,
                 merkle_root: str,
                 timestamp: float = None,
                 nonce: int = 0,
                 difficulty: int = 4,
                 version: int = 1):
        self.previous_hash = previous_hash
        self.merkle_root = merkle_root
        self.timestamp = timestamp or time.time()
        self.nonce = nonce
        self.difficulty = difficulty
        self.version = version
        self.hash = None
    
    def calculate_hash(self) -> str:
        """Calculate the hash of the block header"""
        header_data = {
            'previous_hash': self.previous_hash,
            'merkle_root': self.merkle_root,
            'timestamp': self.timestamp,
            'nonce': self.nonce,
            'difficulty': self.difficulty,
            'version': self.version
        }
        
        header_string = json.dumps(header_data, sort_keys=True)
        return hashlib.sha256(header_string.encode()).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert header to dictionary"""
        return {
            'previous_hash': self.previous_hash,
            'merkle_root': self.merkle_root,
            'timestamp': self.timestamp,
            'nonce': self.nonce,
            'difficulty': self.difficulty,
            'version': self.version,
            'hash': self.hash
        }


class Block:
    """Block class representing a block in the blockchain"""
    
    def __init__(self, 
                 transactions: List[Transaction],
                 previous_hash: str,
                 block_height: int = 0,
                 difficulty: int = 4,
                 miner_address: str = None,
                 block_reward: float = 50.0):
        """
        Initialize a new block
        
        Args:
            transactions: List of transactions to include in the block
            previous_hash: Hash of the previous block
            block_height: Height of this block in the chain
            difficulty: Mining difficulty for this block
            miner_address: Address of the miner who mined this block
            block_reward: Reward for mining this block
        """
        self.transactions = transactions
        self.block_height = block_height
        self.miner_address = miner_address
        self.block_reward = block_reward
        self.timestamp = time.time()
        
        # Build Merkle tree
        self.merkle_tree = MerkleTree(transactions)
        
        # Create block header
        self.header = BlockHeader(
            previous_hash=previous_hash,
            merkle_root=self.merkle_tree.get_root_hash(),
            timestamp=self.timestamp,
            difficulty=difficulty
        )
        
        # Block validation status
        self.is_valid = False
        self.confirmations = 0
        
        # Calculate initial hash
        self.hash = None
        self.calculate_hash()
    
    def calculate_hash(self) -> str:
        """Calculate the hash of the block"""
        self.hash = self.header.calculate_hash()
        self.header.hash = self.hash
        return self.hash
    
    def mine_block(self) -> bool:
        """Mine the block using Proof of Work"""
        target = "0" * self.header.difficulty
        
        print(f"Mining block {self.block_height} with difficulty {self.header.difficulty}...")
        start_time = time.time()
        
        while not self.hash.startswith(target):
            self.header.nonce += 1
            self.calculate_hash()
            
            # Progress indicator
            if self.header.nonce % 100000 == 0:
                elapsed = time.time() - start_time
                print(f"Nonce: {self.header.nonce}, Hash: {self.hash[:20]}..., Time: {elapsed:.2f}s")
        
        mining_time = time.time() - start_time
        print(f"Block mined! Nonce: {self.header.nonce}, Hash: {self.hash}, Time: {mining_time:.2f}s")
        return True
    
    def validate_block(self, previous_block: Optional['Block'] = None) -> bool:
        """Validate the block"""
        # Check if block is already validated
        if self.is_valid:
            return True
        
        # Validate block hash
        calculated_hash = self.header.calculate_hash()
        if calculated_hash != self.hash:
            return False
        
        # Check proof of work
        target = "0" * self.header.difficulty
        if not self.hash.startswith(target):
            return False
        
        # Validate previous hash
        if previous_block and self.header.previous_hash != previous_block.hash:
            return False
        
        # Validate Merkle root
        if self.merkle_tree.get_root_hash() != self.header.merkle_root:
            return False
        
        # Validate all transactions
        for transaction in self.transactions:
            if not transaction.is_valid:
                return False
        
        # Check block size limits
        if len(self.transactions) > 1000:  # Max transactions per block
            return False
        
        # Validate timestamp (not too far in the future)
        current_time = time.time()
        if self.timestamp > current_time + 7200:  # 2 hours in the future
            return False
        
        self.is_valid = True
        return True
    
    def get_transaction_by_id(self, tx_id: str) -> Optional[Transaction]:
        """Get a transaction by its ID"""
        for tx in self.transactions:
            if tx.tx_id == tx_id:
                return tx
        return None
    
    def get_block_size(self) -> int:
        """Get the size of the block in bytes"""
        return len(json.dumps(self.to_dict()).encode())
    
    def get_total_fees(self) -> float:
        """Calculate total transaction fees in the block"""
        return sum(tx.calculate_fee() for tx in self.transactions)
    
    def get_coinbase_transaction(self) -> Optional[Transaction]:
        """Get the coinbase transaction (mining reward)"""
        for tx in self.transactions:
            if tx.tx_type == "COINBASE":
                return tx
        return None
    
    def add_coinbase_transaction(self, miner_address: str) -> Transaction:
        """Add coinbase transaction for mining reward"""
        from .transaction import TransactionOutput
        
        coinbase_tx = Transaction(
            sender="SYSTEM",
            tx_type="COINBASE"
        )
        
        # Add mining reward output
        reward_output = TransactionOutput(
            amount=self.block_reward + self.get_total_fees(),
            recipient=miner_address
        )
        coinbase_tx.outputs.append(reward_output)
        coinbase_tx.set_transaction_id()
        coinbase_tx.is_valid = True
        
        # Insert at the beginning of transactions list
        self.transactions.insert(0, coinbase_tx)
        
        # Rebuild Merkle tree
        self.merkle_tree = MerkleTree(self.transactions)
        self.header.merkle_root = self.merkle_tree.get_root_hash()
        
        return coinbase_tx
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert block to dictionary"""
        return {
            'hash': self.hash,
            'header': self.header.to_dict(),
            'block_height': self.block_height,
            'miner_address': self.miner_address,
            'block_reward': self.block_reward,
            'timestamp': self.timestamp,
            'transactions': [tx.to_dict() for tx in self.transactions],
            'transaction_count': len(self.transactions),
            'block_size': self.get_block_size(),
            'total_fees': self.get_total_fees(),
            'is_valid': self.is_valid,
            'confirmations': self.confirmations
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Block':
        """Create block from dictionary"""
        # Reconstruct transactions
        transactions = [Transaction.from_dict(tx_data) for tx_data in data.get('transactions', [])]
        
        # Create block
        block = cls(
            transactions=transactions,
            previous_hash=data['header']['previous_hash'],
            block_height=data.get('block_height', 0),
            difficulty=data['header']['difficulty'],
            miner_address=data.get('miner_address'),
            block_reward=data.get('block_reward', 50.0)
        )
        
        # Set properties from data
        block.hash = data.get('hash')
        block.timestamp = data.get('timestamp', time.time())
        block.is_valid = data.get('is_valid', False)
        block.confirmations = data.get('confirmations', 0)
        
        # Reconstruct header
        header_data = data.get('header', {})
        block.header.nonce = header_data.get('nonce', 0)
        block.header.hash = header_data.get('hash')
        
        return block
    
    def __str__(self) -> str:
        return f"Block(height={self.block_height}, hash={self.hash[:8]}..., txs={len(self.transactions)})"
    
    def __repr__(self) -> str:
        return self.__str__()


class GenesisBlock(Block):
    """Special genesis block (first block in the chain)"""
    
    def __init__(self, initial_supply: float = 1000000.0, genesis_address: str = "GENESIS"):
        # Create genesis transaction
        from .transaction import TransactionOutput
        
        genesis_tx = Transaction(
            sender="SYSTEM",
            tx_type="GENESIS"
        )
        
        # Add initial supply output
        genesis_output = TransactionOutput(
            amount=initial_supply,
            recipient=genesis_address
        )
        genesis_tx.outputs.append(genesis_output)
        genesis_tx.set_transaction_id()
        genesis_tx.is_valid = True
        
        # Initialize block with genesis transaction
        super().__init__(
            transactions=[genesis_tx],
            previous_hash="0" * 64,  # Genesis block has no previous block
            block_height=0,
            difficulty=1,  # Lower difficulty for genesis block
            miner_address="GENESIS",
            block_reward=0.0  # No mining reward for genesis block
        )
        
        # Genesis block is pre-mined
        self.header.nonce = 0
        self.calculate_hash()
        self.is_valid = True
        
        print(f"Genesis block created: {self.hash}")