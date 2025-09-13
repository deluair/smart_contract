import unittest
import time
import json
from decimal import Decimal
from unittest.mock import Mock, patch, MagicMock

# Import blockchain components
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blockchain.core.block import Block, BlockHeader, GenesisBlock
from blockchain.core.transaction import Transaction, TransactionInput, TransactionOutput
from blockchain.core.blockchain import Blockchain
from blockchain.consensus.pos import ProofOfStakeConsensus, Validator, ValidatorStatus
from security.cryptography import ECDSAKeyPair, CryptoUtils
from security.signatures import TransactionSigner, SignatureData

class TestTransaction(unittest.TestCase):
    """Test cases for Transaction class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.key_pair = ECDSAKeyPair.generate()
        self.signer = TransactionSigner()
        
    def test_transaction_creation(self):
        """Test basic transaction creation"""
        # Create transaction inputs
        tx_input = TransactionInput(
            tx_id="prev_hash_123",
            output_index=0,
            signature="signature_script",
            public_key="public_key_123"
        )
        
        # Create transaction outputs
        tx_output = TransactionOutput(
            amount=1000000,  # 1 token
            script_pubkey="recipient_address",
            asset_type="NATIVE"
        )
        
        # Create transaction
        transaction = Transaction(
            version=1,
            inputs=[tx_input],
            outputs=[tx_output],
            lock_time=0,
            fee=1000,
            transaction_type="TRANSFER"
        )
        
        # Verify transaction properties
        self.assertEqual(transaction.version, 1)
        self.assertEqual(len(transaction.inputs), 1)
        self.assertEqual(len(transaction.outputs), 1)
        self.assertEqual(transaction.fee, 1000)
        self.assertIsNotNone(transaction.tx_hash)
        self.assertIsNotNone(transaction.timestamp)
        
    def test_transaction_validation(self):
        """Test transaction validation"""
        # Create valid transaction
        tx_input = TransactionInput(
            tx_id="a" * 64,  # Valid hash length
            output_index=0,
            signature="valid_signature",
            public_key="public_key_456"
        )
        
        tx_output = TransactionOutput(
            amount=1000000,
            script_pubkey="valid_address",
            asset_type="NATIVE"
        )
        
        transaction = Transaction(
            version=1,
            inputs=[tx_input],
            outputs=[tx_output],
            lock_time=0,
            fee=1000
        )
        
        # Test validation
        is_valid, errors = transaction.validate()
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)
        
    def test_transaction_invalid_cases(self):
        """Test transaction validation with invalid data"""
        # Test with negative amount
        tx_output = TransactionOutput(
            amount=-1000,  # Invalid negative amount
            script_pubkey="address",
            asset_type="NATIVE"
        )
        
        transaction = Transaction(
            version=1,
            inputs=[],  # No inputs
            outputs=[tx_output],
            lock_time=0,
            fee=1000
        )
        
        is_valid, errors = transaction.validate()
        self.assertFalse(is_valid)
        self.assertGreater(len(errors), 0)
        
    def test_transaction_signing(self):
        """Test transaction signing and verification"""
        # Create transaction
        tx_input = TransactionInput(
            tx_id="prev_hash",
            output_index=0,
            signature="",
            public_key="public_key_789"
        )
        
        tx_output = TransactionOutput(
            amount=1000000,
            script_pubkey="recipient",
            asset_type="NATIVE"
        )
        
        transaction = Transaction(
            version=1,
            inputs=[tx_input],
            outputs=[tx_output],
            lock_time=0,
            fee=1000
        )
        
        # Sign transaction
        private_key = self.key_pair.private_key.hex()
        signature = self.signer.sign_transaction(transaction, private_key)
        
        self.assertIsInstance(signature, SignatureData)
        self.assertIsNotNone(signature.signature)
        self.assertIsNotNone(signature.public_key)
        
        # Verify signature
        is_valid = self.signer.verify_transaction_signature(transaction, signature)
        self.assertTrue(is_valid)

class TestBlock(unittest.TestCase):
    """Test cases for Block class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.key_pair = ECDSAKeyPair.generate()
        
    def test_block_creation(self):
        """Test basic block creation"""
        # Create sample transactions
        transactions = self._create_sample_transactions(3)
        
        # Create block header
        header = BlockHeader(
            version=1,
            previous_hash="0" * 64,
            merkle_root="merkle_root_hash",
            timestamp=int(time.time()),
            difficulty=1000,
            nonce=0
        )
        
        # Create block
        block = Block(
            header=header,
            transactions=transactions
        )
        
        # Verify block properties
        self.assertEqual(block.header.version, 1)
        self.assertEqual(len(block.transactions), 3)
        self.assertIsNotNone(block.block_hash)
        self.assertEqual(block.transaction_count, 3)
        
    def test_block_validation(self):
        """Test block validation"""
        transactions = self._create_sample_transactions(2)
        
        header = BlockHeader(
            version=1,
            previous_hash="a" * 64,
            merkle_root=Block.calculate_merkle_root([tx.tx_hash for tx in transactions]),
            timestamp=int(time.time()),
            difficulty=1000,
            nonce=12345
        )
        
        block = Block(header=header, transactions=transactions)
        
        # Test validation
        is_valid, errors = block.validate()
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)
        
    def test_merkle_root_calculation(self):
        """Test Merkle root calculation"""
        # Test with empty list
        merkle_root = Block.calculate_merkle_root([])
        self.assertEqual(merkle_root, "0" * 64)
        
        # Test with single hash
        single_hash = "a" * 64
        merkle_root = Block.calculate_merkle_root([single_hash])
        self.assertEqual(len(merkle_root), 64)
        
        # Test with multiple hashes
        hashes = ["a" * 64, "b" * 64, "c" * 64]
        merkle_root = Block.calculate_merkle_root(hashes)
        self.assertEqual(len(merkle_root), 64)
        
    def test_block_size_calculation(self):
        """Test block size calculation"""
        transactions = self._create_sample_transactions(5)
        
        header = BlockHeader(
            version=1,
            previous_hash="0" * 64,
            merkle_root="merkle_root",
            timestamp=int(time.time()),
            difficulty=1000,
            nonce=0
        )
        
        block = Block(header=header, transactions=transactions)
        
        # Calculate size
        size = block.calculate_size()
        self.assertGreater(size, 0)
        self.assertIsInstance(size, int)
        
    def _create_sample_transactions(self, count: int) -> list:
        """Helper method to create sample transactions"""
        transactions = []
        
        for i in range(count):
            tx_input = TransactionInput(
                tx_id=f"prev_hash_{i}",
                output_index=i,
                signature=f"signature_{i}",
                public_key=f"public_key_{i}"
            )
            
            tx_output = TransactionOutput(
                amount=1000000 + i * 100000,
                script_pubkey=f"address_{i}",
                asset_type="NATIVE"
            )
            
            transaction = Transaction(
                version=1,
                inputs=[tx_input],
                outputs=[tx_output],
                lock_time=0,
                fee=1000 + i * 100
            )
            
            transactions.append(transaction)
            
        return transactions

class TestBlockchain(unittest.TestCase):
    """Test cases for Blockchain class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.blockchain = Blockchain()
        self.key_pair = ECDSAKeyPair.generate()
        
    def test_blockchain_initialization(self):
        """Test blockchain initialization"""
        self.assertEqual(len(self.blockchain.chain), 1)  # Genesis block
        self.assertEqual(self.blockchain.height, 0)
        self.assertIsNotNone(self.blockchain.genesis_block)
        
    def test_genesis_block_creation(self):
        """Test genesis block creation"""
        genesis = self.blockchain.genesis_block
        
        self.assertEqual(genesis.header.previous_hash, "0" * 64)
        self.assertEqual(genesis.header.version, 1)
        self.assertGreater(genesis.header.timestamp, 0)
        self.assertEqual(len(genesis.transactions), 1)  # Coinbase transaction
        
    def test_add_valid_block(self):
        """Test adding a valid block to the blockchain"""
        # Create a valid block
        transactions = self._create_sample_transactions(2)
        
        # Get previous block hash
        previous_hash = self.blockchain.get_latest_block().block_hash
        
        header = BlockHeader(
            version=1,
            previous_hash=previous_hash,
            merkle_root=Block.calculate_merkle_root([tx.tx_hash for tx in transactions]),
            timestamp=int(time.time()),
            difficulty=1000,
            nonce=12345
        )
        
        block = Block(header=header, transactions=transactions)
        
        # Add block
        result = self.blockchain.add_block(block)
        self.assertTrue(result)
        self.assertEqual(len(self.blockchain.chain), 2)
        self.assertEqual(self.blockchain.height, 1)
        
    def test_add_invalid_block(self):
        """Test adding an invalid block to the blockchain"""
        # Create block with invalid previous hash
        transactions = self._create_sample_transactions(1)
        
        header = BlockHeader(
            version=1,
            previous_hash="invalid_hash",  # Invalid previous hash
            merkle_root=Block.calculate_merkle_root([tx.tx_hash for tx in transactions]),
            timestamp=int(time.time()),
            difficulty=1000,
            nonce=12345
        )
        
        block = Block(header=header, transactions=transactions)
        
        # Try to add invalid block
        result = self.blockchain.add_block(block)
        self.assertFalse(result)
        self.assertEqual(len(self.blockchain.chain), 1)  # Should still be just genesis
        
    def test_blockchain_validation(self):
        """Test full blockchain validation"""
        # Add several valid blocks
        for i in range(3):
            transactions = self._create_sample_transactions(2)
            previous_hash = self.blockchain.get_latest_block().block_hash
            
            header = BlockHeader(
                version=1,
                previous_hash=previous_hash,
                merkle_root=Block.calculate_merkle_root([tx.tx_hash for tx in transactions]),
                timestamp=int(time.time()) + i,
                difficulty=1000,
                nonce=12345 + i
            )
            
            block = Block(header=header, transactions=transactions)
            self.blockchain.add_block(block)
            
        # Validate entire blockchain
        is_valid, errors = self.blockchain.validate_chain()
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)
        
    def test_get_block_by_hash(self):
        """Test retrieving block by hash"""
        # Add a block
        transactions = self._create_sample_transactions(1)
        previous_hash = self.blockchain.get_latest_block().block_hash
        
        header = BlockHeader(
            version=1,
            previous_hash=previous_hash,
            merkle_root=Block.calculate_merkle_root([tx.tx_hash for tx in transactions]),
            timestamp=int(time.time()),
            difficulty=1000,
            nonce=12345
        )
        
        block = Block(header=header, transactions=transactions)
        self.blockchain.add_block(block)
        
        # Retrieve block by hash
        retrieved_block = self.blockchain.get_block_by_hash(block.block_hash)
        self.assertIsNotNone(retrieved_block)
        self.assertEqual(retrieved_block.block_hash, block.block_hash)
        
        # Test with non-existent hash
        non_existent = self.blockchain.get_block_by_hash("non_existent_hash")
        self.assertIsNone(non_existent)
        
    def test_get_transaction_by_hash(self):
        """Test retrieving transaction by hash"""
        # Create and add a block with transactions
        transactions = self._create_sample_transactions(2)
        previous_hash = self.blockchain.get_latest_block().block_hash
        
        header = BlockHeader(
            version=1,
            previous_hash=previous_hash,
            merkle_root=Block.calculate_merkle_root([tx.tx_hash for tx in transactions]),
            timestamp=int(time.time()),
            difficulty=1000,
            nonce=12345
        )
        
        block = Block(header=header, transactions=transactions)
        self.blockchain.add_block(block)
        
        # Retrieve transaction by hash
        tx_hash = transactions[0].tx_hash
        retrieved_tx = self.blockchain.get_transaction_by_hash(tx_hash)
        self.assertIsNotNone(retrieved_tx)
        self.assertEqual(retrieved_tx.tx_hash, tx_hash)
        
    def test_blockchain_statistics(self):
        """Test blockchain statistics calculation"""
        # Add several blocks
        for i in range(5):
            transactions = self._create_sample_transactions(3)
            previous_hash = self.blockchain.get_latest_block().block_hash
            
            header = BlockHeader(
                version=1,
                previous_hash=previous_hash,
                merkle_root=Block.calculate_merkle_root([tx.tx_hash for tx in transactions]),
                timestamp=int(time.time()) + i,
                difficulty=1000,
                nonce=12345 + i
            )
            
            block = Block(header=header, transactions=transactions)
            self.blockchain.add_block(block)
            
        # Get statistics
        stats = self.blockchain.get_statistics()
        
        self.assertEqual(stats['total_blocks'], 6)  # 5 + genesis
        self.assertEqual(stats['blockchain_height'], 5)
        self.assertGreater(stats['total_transactions'], 15)  # At least 15 transactions
        self.assertGreater(stats['total_size'], 0)
        self.assertIsInstance(stats['average_block_time'], (int, float))
        
    def _create_sample_transactions(self, count: int) -> list:
        """Helper method to create sample transactions"""
        transactions = []
        
        for i in range(count):
            tx_input = TransactionInput(
                tx_id=f"prev_hash_{i}_{int(time.time())}",
                output_index=i,
                signature=f"signature_{i}",
                public_key=f"public_key_{i}"
            )
            
            tx_output = TransactionOutput(
                amount=1000000 + i * 100000,
                script_pubkey=f"address_{i}",
                asset_type="NATIVE"
            )
            
            transaction = Transaction(
                version=1,
                inputs=[tx_input],
                outputs=[tx_output],
                lock_time=0,
                fee=1000 + i * 100
            )
            
            transactions.append(transaction)
            
        return transactions

class TestProofOfStakeConsensus(unittest.TestCase):
    """Test cases for Proof of Stake consensus"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.pos_consensus = ProofOfStakeConsensus()
        self.key_pairs = [ECDSAKeyPair.generate() for _ in range(5)]
        
    def test_validator_registration(self):
        """Test validator registration"""
        validator_address = "validator_address_1"
        public_key = self.key_pairs[0].export_public_key()
        stake_amount = 100000
        
        # Register validator
        validator_id = self.pos_consensus.register_validator(
            validator_address, public_key, stake_amount
        )
        
        self.assertIsNotNone(validator_id)
        self.assertIn(validator_id, self.pos_consensus.validators)
        
        validator = self.pos_consensus.validators[validator_id]
        self.assertEqual(validator.address, validator_address)
        self.assertEqual(validator.stake_amount, stake_amount)
        self.assertEqual(validator.status, ValidatorStatus.REGISTERED)
        
    def test_validator_activation(self):
        """Test validator activation"""
        # Register validator
        validator_address = "validator_address_1"
        public_key = self.key_pairs[0].export_public_key()
        stake_amount = 100000
        
        validator_id = self.pos_consensus.register_validator(
            validator_address, public_key, stake_amount
        )
        
        # Activate validator
        result = self.pos_consensus.activate_validator(validator_id)
        self.assertTrue(result)
        
        validator = self.pos_consensus.validators[validator_id]
        self.assertEqual(validator.status, ValidatorStatus.ACTIVE)
        
    def test_block_proposer_selection(self):
        """Test block proposer selection"""
        # Register and activate multiple validators
        validator_ids = []
        for i, key_pair in enumerate(self.key_pairs):
            validator_id = self.pos_consensus.register_validator(
                f"validator_address_{i}",
                key_pair.export_public_key(),
                100000 + i * 50000  # Different stake amounts
            )
            self.pos_consensus.activate_validator(validator_id)
            validator_ids.append(validator_id)
            
        # Select proposer
        proposer_id = self.pos_consensus.select_block_proposer()
        self.assertIsNotNone(proposer_id)
        self.assertIn(proposer_id, validator_ids)
        
    def test_block_validation(self):
        """Test block validation in PoS"""
        # Register and activate a validator
        validator_address = "validator_address_1"
        public_key = self.key_pairs[0].export_public_key()
        stake_amount = 100000
        
        validator_id = self.pos_consensus.register_validator(
            validator_address, public_key, stake_amount
        )
        self.pos_consensus.activate_validator(validator_id)
        
        # Create a mock block
        mock_block = Mock()
        mock_block.header.timestamp = int(time.time())
        mock_block.header.difficulty = 1000
        mock_block.validate.return_value = (True, [])
        
        # Validate block
        is_valid = self.pos_consensus.validate_block(mock_block, validator_id)
        self.assertTrue(is_valid)
        
    def test_delegation(self):
        """Test stake delegation"""
        # Register validator
        validator_address = "validator_address_1"
        public_key = self.key_pairs[0].export_public_key()
        stake_amount = 100000
        
        validator_id = self.pos_consensus.register_validator(
            validator_address, public_key, stake_amount
        )
        
        # Delegate stake
        delegator_address = "delegator_address_1"
        delegation_amount = 50000
        
        result = self.pos_consensus.delegate_stake(
            delegator_address, validator_id, delegation_amount
        )
        self.assertTrue(result)
        
        # Check delegation
        validator = self.pos_consensus.validators[validator_id]
        self.assertEqual(validator.total_delegated_stake, delegation_amount)
        self.assertIn(delegator_address, validator.delegators)
        
    def test_reward_distribution(self):
        """Test reward distribution"""
        # Register and activate validator with delegators
        validator_address = "validator_address_1"
        public_key = self.key_pairs[0].export_public_key()
        stake_amount = 100000
        
        validator_id = self.pos_consensus.register_validator(
            validator_address, public_key, stake_amount
        )
        self.pos_consensus.activate_validator(validator_id)
        
        # Add delegation
        self.pos_consensus.delegate_stake("delegator_1", validator_id, 50000)
        
        # Distribute rewards
        total_reward = 10000
        self.pos_consensus.distribute_rewards(validator_id, total_reward)
        
        validator = self.pos_consensus.validators[validator_id]
        self.assertGreater(validator.total_rewards, 0)
        
    def test_slashing(self):
        """Test validator slashing"""
        # Register and activate validator
        validator_address = "validator_address_1"
        public_key = self.key_pairs[0].export_public_key()
        stake_amount = 100000
        
        validator_id = self.pos_consensus.register_validator(
            validator_address, public_key, stake_amount
        )
        self.pos_consensus.activate_validator(validator_id)
        
        # Slash validator
        slash_amount = 10000
        reason = "Double signing"
        
        result = self.pos_consensus.slash_validator(validator_id, slash_amount, reason)
        self.assertTrue(result)
        
        validator = self.pos_consensus.validators[validator_id]
        self.assertEqual(validator.slashed_amount, slash_amount)
        self.assertEqual(validator.status, ValidatorStatus.SLASHED)

if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_suite.addTest(unittest.makeSuite(TestTransaction))
    test_suite.addTest(unittest.makeSuite(TestBlock))
    test_suite.addTest(unittest.makeSuite(TestBlockchain))
    test_suite.addTest(unittest.makeSuite(TestProofOfStakeConsensus))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    print(f"\n{'='*50}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    print(f"{'='*50}")