import json
import os
import time
import threading
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict
from .block import Block, GenesisBlock
from .transaction import Transaction, TransactionPool, TransactionOutput


class UTXO:
    """Unspent Transaction Output"""
    
    def __init__(self, tx_id: str, output_index: int, amount: float, 
                 recipient: str, asset_type: str = "COIN", block_height: int = 0):
        self.tx_id = tx_id
        self.output_index = output_index
        self.amount = amount
        self.recipient = recipient
        self.asset_type = asset_type
        self.block_height = block_height
        self.is_spent = False
    
    def get_key(self) -> str:
        """Get the unique key for this UTXO"""
        return f"{self.tx_id}:{self.output_index}"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'tx_id': self.tx_id,
            'output_index': self.output_index,
            'amount': self.amount,
            'recipient': self.recipient,
            'asset_type': self.asset_type,
            'block_height': self.block_height,
            'is_spent': self.is_spent
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'UTXO':
        utxo = cls(
            tx_id=data['tx_id'],
            output_index=data['output_index'],
            amount=data['amount'],
            recipient=data['recipient'],
            asset_type=data.get('asset_type', 'COIN'),
            block_height=data.get('block_height', 0)
        )
        utxo.is_spent = data.get('is_spent', False)
        return utxo


class Blockchain:
    """Main blockchain class managing the chain of blocks"""
    
    def __init__(self, 
                 data_dir: str = "blockchain_data",
                 initial_difficulty: int = 4,
                 block_time_target: int = 600,  # 10 minutes
                 max_block_size: int = 1000000,  # 1MB
                 block_reward: float = 50.0):
        """
        Initialize the blockchain
        
        Args:
            data_dir: Directory to store blockchain data
            initial_difficulty: Initial mining difficulty
            block_time_target: Target time between blocks in seconds
            max_block_size: Maximum block size in bytes
            block_reward: Mining reward per block
        """
        self.data_dir = data_dir
        self.initial_difficulty = initial_difficulty
        self.block_time_target = block_time_target
        self.max_block_size = max_block_size
        self.block_reward = block_reward
        
        # Core blockchain data
        self.chain: List[Block] = []
        self.genesis_block: Optional[Block] = None
        self.utxo_set: Dict[str, UTXO] = {}  # Unspent transaction outputs
        self.transaction_pool = TransactionPool()
        
        # Blockchain height property
        self.height = 0
        
        # Blockchain state
        self.current_difficulty = initial_difficulty
        self.total_supply = 0.0
        self.chain_work = 0  # Total work done on the chain
        
        # Threading locks
        self.chain_lock = threading.RLock()
        self.utxo_lock = threading.RLock()
        
        # Performance metrics
        self.block_times: List[float] = []
        self.hash_rate = 0.0
        
        # Initialize blockchain
        self._ensure_data_directory()
        self._load_or_create_genesis()
    
    def _ensure_data_directory(self):
        """Ensure the data directory exists"""
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
    
    def _load_or_create_genesis(self):
        """Load existing blockchain or create genesis block"""
        genesis_file = os.path.join(self.data_dir, "genesis.json")
        
        if os.path.exists(genesis_file):
            self._load_blockchain()
        else:
            self._create_genesis_block()
            self._save_blockchain()
        
        # Update height after loading/creating
        self.height = len(self.chain) - 1 if self.chain else 0
    
    def _create_genesis_block(self):
        """Create the genesis block"""
        print("Creating genesis block...")
        genesis_block = GenesisBlock()
        
        with self.chain_lock:
            self.chain.append(genesis_block)
            self.genesis_block = genesis_block
        
        # Add genesis UTXO to UTXO set
        self._update_utxo_set(genesis_block)
        
        print(f"Genesis block created with hash: {genesis_block.hash}")
    
    def _update_utxo_set(self, block: Block):
        """Update UTXO set with new block"""
        with self.utxo_lock:
            # Remove spent UTXOs
            for tx in block.transactions:
                for tx_input in tx.inputs:
                    utxo_key = f"{tx_input.tx_id}:{tx_input.output_index}"
                    if utxo_key in self.utxo_set:
                        del self.utxo_set[utxo_key]
            
            # Add new UTXOs
            for tx in block.transactions:
                for i, output in enumerate(tx.outputs):
                    utxo = UTXO(
                        tx_id=tx.tx_id,
                        output_index=i,
                        amount=output.amount,
                        recipient=output.recipient,
                        asset_type=output.asset_type,
                        block_height=block.block_height
                    )
                    self.utxo_set[utxo.get_key()] = utxo
    
    def get_latest_block(self) -> Optional[Block]:
        """Get the latest block in the chain"""
        with self.chain_lock:
            return self.chain[-1] if self.chain else None
    
    def get_block_by_hash(self, block_hash: str) -> Optional[Block]:
        """Get a block by its hash"""
        with self.chain_lock:
            for block in self.chain:
                if block.hash == block_hash:
                    return block
        return None
    
    def get_block_by_height(self, height: int) -> Optional[Block]:
        """Get a block by its height"""
        with self.chain_lock:
            if 0 <= height < len(self.chain):
                return self.chain[height]
        return None
    
    def get_transaction_by_id(self, tx_id: str) -> Optional[Tuple[Transaction, Block]]:
        """Get a transaction by its ID along with the containing block"""
        with self.chain_lock:
            for block in self.chain:
                tx = block.get_transaction_by_id(tx_id)
                if tx:
                    return tx, block
        return None
    
    def get_transaction_by_hash(self, tx_hash: str) -> Optional[Transaction]:
        """Get a transaction by its hash (alias for get_transaction_by_id)"""
        result = self.get_transaction_by_id(tx_hash)
        return result[0] if result else None
    
    def get_balance(self, address: str, asset_type: str = "COIN") -> float:
        """Get the balance for an address"""
        balance = 0.0
        with self.utxo_lock:
            for utxo in self.utxo_set.values():
                if utxo.recipient == address and utxo.asset_type == asset_type:
                    balance += utxo.amount
        return balance
    
    def get_utxos_for_address(self, address: str, asset_type: str = "COIN") -> List[UTXO]:
        """Get all UTXOs for an address"""
        utxos = []
        with self.utxo_lock:
            for utxo in self.utxo_set.values():
                if utxo.recipient == address and utxo.asset_type == asset_type:
                    utxos.append(utxo)
        return utxos
    
    def add_transaction(self, transaction: Transaction) -> bool:
        """Add a transaction to the transaction pool"""
        # Validate transaction
        if not self.validate_transaction(transaction):
            return False
        
        return self.transaction_pool.add_transaction(transaction)
    
    def validate_transaction(self, transaction: Transaction) -> bool:
        """Validate a transaction against the current UTXO set"""
        with self.utxo_lock:
            utxo_dict = {utxo.get_key(): utxo.to_dict() for utxo in self.utxo_set.values()}
            return transaction.validate_transaction(utxo_dict)
    
    def create_block(self, miner_address: str) -> Optional[Block]:
        """Create a new block with pending transactions"""
        latest_block = self.get_latest_block()
        if not latest_block:
            return None
        
        # Get transactions from pool
        transactions = self.transaction_pool.get_transactions_for_block()
        
        # Filter valid transactions
        valid_transactions = []
        for tx in transactions:
            if self.validate_transaction(tx):
                valid_transactions.append(tx)
        
        # Create new block
        new_block = Block(
            transactions=valid_transactions,
            previous_hash=latest_block.hash,
            block_height=latest_block.block_height + 1,
            difficulty=self.current_difficulty,
            miner_address=miner_address,
            block_reward=self.block_reward
        )
        
        # Add coinbase transaction
        new_block.add_coinbase_transaction(miner_address)
        
        return new_block
    
    def add_block(self, block: Block) -> bool:
        """Add a new block to the blockchain"""
        latest_block = self.get_latest_block()
        
        # Validate block
        if not block.validate_block(latest_block):
            print(f"Block validation failed: {block.hash}")
            return False
        
        # Check if block already exists
        if self.get_block_by_hash(block.hash):
            print(f"Block already exists: {block.hash}")
            return False
        
        # Add block to chain
        with self.chain_lock:
            self.chain.append(block)
            block.confirmations = 1
            
            # Update height
            self.height = len(self.chain) - 1
            
            # Update confirmations for previous blocks
            for i in range(len(self.chain) - 2, -1, -1):
                self.chain[i].confirmations += 1
        
        # Update UTXO set
        self._update_utxo_set(block)
        
        # Remove transactions from pool
        tx_ids = [tx.tx_id for tx in block.transactions]
        self.transaction_pool.clear_transactions(tx_ids)
        
        # Update blockchain metrics
        self._update_metrics(block)
        
        # Adjust difficulty if needed
        self._adjust_difficulty()
        
        print(f"Block added: {block.hash[:16]}... (Height: {block.block_height})")
        return True
    
    def mine_block(self, miner_address: str) -> Optional[Block]:
        """Mine a new block"""
        block = self.create_block(miner_address)
        if not block:
            return None
        
        # Mine the block
        if block.mine_block():
            if self.add_block(block):
                return block
        
        return None
    
    def _update_metrics(self, block: Block):
        """Update blockchain performance metrics"""
        # Update block times
        if len(self.chain) > 1:
            previous_block = self.chain[-2]
            block_time = block.timestamp - previous_block.timestamp
            self.block_times.append(block_time)
            
            # Keep only last 100 block times
            if len(self.block_times) > 100:
                self.block_times.pop(0)
        
        # Update total supply
        self.total_supply += block.block_reward
        
        # Update chain work (simplified)
        self.chain_work += 2 ** block.header.difficulty
    
    def _adjust_difficulty(self):
        """Adjust mining difficulty based on block times"""
        if len(self.block_times) < 10:  # Need at least 10 blocks
            return
        
        # Calculate average block time for last 10 blocks
        recent_times = self.block_times[-10:]
        avg_time = sum(recent_times) / len(recent_times)
        
        # Adjust difficulty
        if avg_time < self.block_time_target * 0.8:  # Too fast
            self.current_difficulty += 1
            print(f"Difficulty increased to {self.current_difficulty}")
        elif avg_time > self.block_time_target * 1.2:  # Too slow
            if self.current_difficulty > 1:
                self.current_difficulty -= 1
                print(f"Difficulty decreased to {self.current_difficulty}")
    
    def get_chain_info(self) -> Dict[str, Any]:
        """Get information about the blockchain"""
        latest_block = self.get_latest_block()
        
        return {
            'chain_length': len(self.chain),
            'latest_block_hash': latest_block.hash if latest_block else None,
            'latest_block_height': latest_block.block_height if latest_block else 0,
            'current_difficulty': self.current_difficulty,
            'total_supply': self.total_supply,
            'pending_transactions': self.transaction_pool.get_pool_size(),
            'utxo_count': len(self.utxo_set),
            'chain_work': self.chain_work,
            'avg_block_time': sum(self.block_times) / len(self.block_times) if self.block_times else 0
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get blockchain statistics"""
        with self.chain_lock:
            total_transactions = sum(len(block.transactions) for block in self.chain)
            avg_block_time = sum(self.block_times) / len(self.block_times) if self.block_times else 0
            
            return {
                'height': self.height,
                'total_blocks': len(self.chain),
                'total_transactions': total_transactions,
                'total_supply': self.total_supply,
                'current_difficulty': self.current_difficulty,
                'average_block_time': avg_block_time,
                'hash_rate': self.hash_rate,
                'chain_work': self.chain_work
            }
    
    def validate_chain(self) -> Tuple[bool, List[str]]:
        """Validate the entire blockchain and return validation result with errors"""
        print("Validating blockchain...")
        
        with self.chain_lock:
            errors = []
            
            if not self.chain:
                return True, errors
            
            # Validate genesis block
            if not isinstance(self.chain[0], GenesisBlock):
                errors.append("First block is not a genesis block")
                return False, errors
            
            # Validate each block
            for i in range(1, len(self.chain)):
                current_block = self.chain[i]
                previous_block = self.chain[i - 1]
                
                if not current_block.validate_block(previous_block):
                    errors.append(f"Block {i} validation failed")
            
            is_valid = len(errors) == 0
            if is_valid:
                print("Blockchain validation successful")
            else:
                print(f"Blockchain validation failed with {len(errors)} errors")
            
            return is_valid, errors
    
    def _save_blockchain(self):
        """Save blockchain to disk"""
        try:
            # Save chain
            chain_file = os.path.join(self.data_dir, "chain.json")
            with open(chain_file, 'w') as f:
                chain_data = [block.to_dict() for block in self.chain]
                json.dump(chain_data, f, indent=2)
            
            # Save UTXO set
            utxo_file = os.path.join(self.data_dir, "utxos.json")
            with open(utxo_file, 'w') as f:
                utxo_data = {key: utxo.to_dict() for key, utxo in self.utxo_set.items()}
                json.dump(utxo_data, f, indent=2)
            
            # Save metadata
            meta_file = os.path.join(self.data_dir, "metadata.json")
            with open(meta_file, 'w') as f:
                metadata = {
                    'current_difficulty': self.current_difficulty,
                    'total_supply': self.total_supply,
                    'chain_work': self.chain_work,
                    'block_times': self.block_times
                }
                json.dump(metadata, f, indent=2)
            
            print("Blockchain saved to disk")
        except Exception as e:
            print(f"Error saving blockchain: {e}")
    
    def _load_blockchain(self):
        """Load blockchain from disk"""
        try:
            # Load chain
            chain_file = os.path.join(self.data_dir, "chain.json")
            if os.path.exists(chain_file):
                with open(chain_file, 'r') as f:
                    chain_data = json.load(f)
                    self.chain = [Block.from_dict(block_data) for block_data in chain_data]
                    if self.chain:
                        self.genesis_block = self.chain[0]
            
            # Load UTXO set
            utxo_file = os.path.join(self.data_dir, "utxos.json")
            if os.path.exists(utxo_file):
                with open(utxo_file, 'r') as f:
                    utxo_data = json.load(f)
                    self.utxo_set = {key: UTXO.from_dict(data) for key, data in utxo_data.items()}
            
            # Load metadata
            meta_file = os.path.join(self.data_dir, "metadata.json")
            if os.path.exists(meta_file):
                with open(meta_file, 'r') as f:
                    metadata = json.load(f)
                    self.current_difficulty = metadata.get('current_difficulty', self.initial_difficulty)
                    self.total_supply = metadata.get('total_supply', 0.0)
                    self.chain_work = metadata.get('chain_work', 0)
                    self.block_times = metadata.get('block_times', [])
            
            print(f"Blockchain loaded: {len(self.chain)} blocks")
        except Exception as e:
            print(f"Error loading blockchain: {e}")
            self._create_genesis_block()
    
    def shutdown(self):
        """Shutdown the blockchain and save data"""
        print("Shutting down blockchain...")
        self._save_blockchain()
        print("Blockchain shutdown complete")
    
    def __str__(self) -> str:
        return f"Blockchain(blocks={len(self.chain)}, difficulty={self.current_difficulty}, supply={self.total_supply})"
    
    def __repr__(self) -> str:
        return self.__str__()


# Utility functions
def create_sample_transaction(blockchain: Blockchain, sender: str, recipient: str, amount: float) -> Optional[Transaction]:
    """Create a sample transaction"""
    from .transaction import TransactionInput, TransactionOutput
    
    # Get UTXOs for sender
    utxos = blockchain.get_utxos_for_address(sender)
    
    # Select UTXOs to spend
    selected_utxos = []
    total_input = 0.0
    
    for utxo in utxos:
        selected_utxos.append(utxo)
        total_input += utxo.amount
        if total_input >= amount:
            break
    
    if total_input < amount:
        print(f"Insufficient balance: {total_input} < {amount}")
        return None
    
    # Create transaction inputs
    inputs = []
    for utxo in selected_utxos:
        tx_input = TransactionInput(
            tx_id=utxo.tx_id,
            output_index=utxo.output_index
        )
        inputs.append(tx_input)
    
    # Create transaction outputs
    outputs = []
    
    # Output to recipient
    recipient_output = TransactionOutput(
        amount=amount,
        recipient=recipient
    )
    outputs.append(recipient_output)
    
    # Change output back to sender
    change = total_input - amount - 0.001  # 0.001 as fee
    if change > 0:
        change_output = TransactionOutput(
            amount=change,
            recipient=sender
        )
        outputs.append(change_output)
    
    # Create transaction
    transaction = Transaction(
        sender=sender,
        inputs=inputs,
        outputs=outputs
    )
    
    transaction.set_transaction_id()
    return transaction