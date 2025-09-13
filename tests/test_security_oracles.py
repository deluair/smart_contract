import unittest
import time
import json
import hashlib
import secrets
from decimal import Decimal
from unittest.mock import Mock, patch, MagicMock

# Import security and oracle components
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security.cryptography import ECDSAKeyPair, CryptoUtils, EncryptionResult
from security.signatures import (
    SignatureData, TransactionSigner, BlockSigner, 
    SmartContractSigner, MultiSigManager, SignatureValidator, SignatureAggregator
)
from oracles.price_feed import (
    PriceFeedManager, PriceData, AggregatedPrice, DataSource, 
    OracleNode, AggregationMethod
)
from oracles.oracle_manager import (
    OracleManager, DataRequest, OracleResponse, Dispute, 
    OracleReputation, OracleType, DataRequestStatus, DisputeStatus
)
from wallet.wallet import Wallet, HDWallet, Account, MultiSigConfig
from wallet.account_manager import AccountManager, UserRole, PermissionType

class TestCryptography(unittest.TestCase):
    """Test cases for cryptographic functions"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.crypto_utils = CryptoUtils()
        
    def test_ecdsa_key_generation(self):
        """Test ECDSA key pair generation"""
        key_pair = ECDSAKeyPair.generate()
        
        self.assertIsNotNone(key_pair.private_key)
        self.assertIsNotNone(key_pair.public_key)
        self.assertEqual(len(key_pair.private_key), 32)  # 256 bits
        self.assertGreater(len(key_pair.public_key), 32)  # Compressed or uncompressed
        
    def test_ecdsa_key_from_private(self):
        """Test ECDSA key pair creation from private key"""
        # Generate a key pair
        original_pair = ECDSAKeyPair.generate()
        private_key_bytes = original_pair.private_key
        
        # Recreate from private key
        recreated_pair = ECDSAKeyPair.from_private_key(private_key_bytes)
        
        self.assertEqual(original_pair.private_key, recreated_pair.private_key)
        self.assertEqual(original_pair.public_key, recreated_pair.public_key)
        
    def test_address_generation(self):
        """Test address generation from public key"""
        key_pair = ECDSAKeyPair.generate()
        address = key_pair.get_address()
        
        self.assertIsNotNone(address)
        self.assertIsInstance(address, str)
        self.assertTrue(address.startswith('0x'))
        self.assertEqual(len(address), 42)  # 0x + 40 hex characters
        
    def test_message_signing_and_verification(self):
        """Test message signing and verification"""
        key_pair = ECDSAKeyPair.generate()
        message = b"Hello, blockchain!"
        
        # Sign message
        signature = key_pair.sign_message(message)
        
        self.assertIsNotNone(signature)
        self.assertIsInstance(signature, bytes)
        
        # Verify signature
        is_valid = key_pair.verify_signature(message, signature)
        self.assertTrue(is_valid)
        
        # Test with wrong message
        wrong_message = b"Wrong message"
        is_valid_wrong = key_pair.verify_signature(wrong_message, signature)
        self.assertFalse(is_valid_wrong)
        
    def test_encryption_decryption(self):
        """Test symmetric encryption and decryption"""
        plaintext = "This is a secret message"
        password = "strong_password_123"
        
        # Encrypt
        encrypted_result = self.crypto_utils.encrypt_data(plaintext, password)
        
        self.assertIsInstance(encrypted_result, EncryptionResult)
        self.assertIsNotNone(encrypted_result.ciphertext)
        self.assertIsNotNone(encrypted_result.salt)
        self.assertIsNotNone(encrypted_result.iv)
        
        # Decrypt
        decrypted_text = self.crypto_utils.decrypt_data(
            encrypted_result.ciphertext,
            password,
            encrypted_result.salt,
            encrypted_result.iv
        )
        
        self.assertEqual(plaintext, decrypted_text)
        
    def test_hash_functions(self):
        """Test various hash functions"""
        data = "test data for hashing"
        
        # Test SHA-256
        sha256_hash = self.crypto_utils.sha256(data)
        self.assertEqual(len(sha256_hash), 64)  # 32 bytes = 64 hex chars
        
        # Test SHA-3
        sha3_hash = self.crypto_utils.sha3_256(data)
        self.assertEqual(len(sha3_hash), 64)
        
        # Test BLAKE2b
        blake2b_hash = self.crypto_utils.blake2b(data)
        self.assertEqual(len(blake2b_hash), 128)  # 64 bytes = 128 hex chars
        
        # Ensure different algorithms produce different hashes
        self.assertNotEqual(sha256_hash, sha3_hash)
        self.assertNotEqual(sha256_hash, blake2b_hash)
        
    def test_merkle_tree(self):
        """Test Merkle tree construction"""
        data_list = ["data1", "data2", "data3", "data4"]
        
        merkle_root = self.crypto_utils.calculate_merkle_root(data_list)
        
        self.assertIsNotNone(merkle_root)
        self.assertEqual(len(merkle_root), 64)  # SHA-256 hash
        
        # Test with empty list
        empty_root = self.crypto_utils.calculate_merkle_root([])
        self.assertEqual(empty_root, "0" * 64)
        
        # Test with single item
        single_root = self.crypto_utils.calculate_merkle_root(["single"])
        self.assertEqual(len(single_root), 64)

class TestSignatures(unittest.TestCase):
    """Test cases for digital signatures"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.key_pair = ECDSAKeyPair.generate()
        self.transaction_signer = TransactionSigner()
        self.block_signer = BlockSigner()
        self.contract_signer = SmartContractSigner()
        
    def test_signature_data_creation(self):
        """Test SignatureData creation"""
        signature = "signature_hex"
        public_key = self.key_pair.export_public_key()
        message_hash = "message_hash_hex"
        
        sig_data = SignatureData(
            signature=signature,
            public_key=public_key,
            message_hash=message_hash
        )
        
        self.assertEqual(sig_data.signature, signature)
        self.assertEqual(sig_data.public_key, public_key)
        self.assertEqual(sig_data.message_hash, message_hash)
        self.assertIsNotNone(sig_data.timestamp)
        
    def test_transaction_signing(self):
        """Test transaction signing"""
        # Create mock transaction
        mock_transaction = Mock()
        mock_transaction.to_dict.return_value = {
            'version': 1,
            'inputs': [],
            'outputs': [],
            'fee': 1000
        }
        
        private_key = self.key_pair.private_key.hex()
        
        # Sign transaction
        signature_data = self.transaction_signer.sign_transaction(
            mock_transaction, private_key
        )
        
        self.assertIsInstance(signature_data, SignatureData)
        self.assertIsNotNone(signature_data.signature)
        self.assertIsNotNone(signature_data.public_key)
        
        # Verify signature
        is_valid = self.transaction_signer.verify_transaction_signature(
            mock_transaction, signature_data
        )
        self.assertTrue(is_valid)
        
    def test_block_signing(self):
        """Test block signing"""
        # Create mock block
        mock_block = Mock()
        mock_block.to_dict.return_value = {
            'header': {
                'version': 1,
                'previous_hash': 'prev_hash',
                'merkle_root': 'merkle_root',
                'timestamp': int(time.time())
            },
            'transactions': []
        }
        
        private_key = self.key_pair.private_key.hex()
        
        # Sign block
        signature_data = self.block_signer.sign_block(mock_block, private_key)
        
        self.assertIsInstance(signature_data, SignatureData)
        
        # Verify signature
        is_valid = self.block_signer.verify_block_signature(
            mock_block, signature_data
        )
        self.assertTrue(is_valid)
        
    def test_smart_contract_signing(self):
        """Test smart contract signing"""
        contract_data = {
            'bytecode': '608060405234801561001057600080fd5b50',
            'constructor_args': [],
            'deployer': '0x123'
        }
        
        private_key = self.key_pair.private_key.hex()
        
        # Sign contract
        signature_data = self.contract_signer.sign_contract(
            contract_data, private_key
        )
        
        self.assertIsInstance(signature_data, SignatureData)
        
        # Verify signature
        is_valid = self.contract_signer.verify_contract_signature(
            contract_data, signature_data
        )
        self.assertTrue(is_valid)
        
    def test_multisig_manager(self):
        """Test multi-signature management"""
        # Create multiple key pairs
        key_pairs = [ECDSAKeyPair.generate() for _ in range(3)]
        public_keys = [kp.export_public_key() for kp in key_pairs]
        
        multisig_manager = MultiSigManager()
        
        # Create multisig wallet
        wallet_address = multisig_manager.create_multisig_wallet(
            public_keys, required_signatures=2
        )
        
        self.assertIsNotNone(wallet_address)
        
        # Create transaction proposal
        transaction_data = {
            'to': '0x456',
            'amount': 1000,
            'data': ''
        }
        
        proposal_id = multisig_manager.create_transaction_proposal(
            wallet_address, transaction_data, key_pairs[0].get_address()
        )
        
        self.assertIsNotNone(proposal_id)
        
        # Sign proposal
        for i in range(2):  # Sign with 2 out of 3 keys
            private_key = key_pairs[i].private_key.hex()
            success = multisig_manager.sign_transaction_proposal(
                proposal_id, private_key
            )
            self.assertTrue(success)
            
        # Execute transaction
        success = multisig_manager.execute_transaction(proposal_id)
        self.assertTrue(success)
        
    def test_signature_validator(self):
        """Test signature validation"""
        validator = SignatureValidator()
        
        # Create valid signature
        message = b"test message"
        signature = self.key_pair.sign_message(message)
        public_key = self.key_pair.export_public_key()
        
        # Validate signature
        is_valid = validator.validate_signature(
            message.hex(), signature.hex(), public_key
        )
        self.assertTrue(is_valid)
        
        # Test with invalid signature
        invalid_signature = "invalid_signature_hex"
        is_valid_invalid = validator.validate_signature(
            message.hex(), invalid_signature, public_key
        )
        self.assertFalse(is_valid_invalid)
        
    def test_signature_aggregator(self):
        """Test signature aggregation"""
        aggregator = SignatureAggregator()
        
        # Create multiple signatures
        signatures = []
        message = b"common message"
        
        for _ in range(3):
            kp = ECDSAKeyPair.generate()
            sig = kp.sign_message(message)
            sig_data = SignatureData(
                signature=sig.hex(),
                public_key=kp.export_public_key(),
                message_hash=hashlib.sha256(message).hexdigest()
            )
            signatures.append(sig_data)
            
        # Aggregate signatures
        aggregated = aggregator.aggregate_signatures(signatures)
        
        self.assertIsNotNone(aggregated)
        self.assertIn('aggregated_signature', aggregated)
        self.assertIn('public_keys', aggregated)
        
        # Verify aggregated signature
        is_valid = aggregator.verify_aggregated_signature(
            message.hex(), aggregated
        )
        self.assertTrue(is_valid)

class TestPriceFeed(unittest.TestCase):
    """Test cases for price feed system"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.price_manager = PriceFeedManager()
        
    def test_data_source_creation(self):
        """Test data source creation"""
        source = DataSource(
            source_id="binance_api",
            name="Binance",
            url="https://api.binance.com",
            api_key="test_key",
            is_active=True,
            reliability_score=95.0,
            supported_pairs=["BTC/USD", "ETH/USD"]
        )
        
        self.assertEqual(source.source_id, "binance_api")
        self.assertEqual(source.name, "Binance")
        self.assertTrue(source.is_active)
        self.assertEqual(source.reliability_score, 95.0)
        
    def test_oracle_node_creation(self):
        """Test oracle node creation"""
        node = OracleNode(
            node_id="oracle_1",
            address="0x123",
            public_key="public_key_hex",
            reputation=Decimal('95.5'),
            stake_amount=100000,
            is_active=True,
            last_update=int(time.time()),
            total_updates=100,
            successful_updates=95,
            failed_updates=5,
            supported_pairs=["BTC/USD", "ETH/USD"]
        )
        
        self.assertEqual(node.node_id, "oracle_1")
        self.assertEqual(node.reputation, Decimal('95.5'))
        self.assertTrue(node.is_active)
        self.assertEqual(node.success_rate, Decimal('95.0'))
        
    def test_price_data_creation(self):
        """Test price data creation"""
        price_data = PriceData(
            symbol="BTC/USD",
            price=Decimal('50000.00'),
            timestamp=int(time.time()),
            source="binance",
            volume=Decimal('1000.0'),
            confidence=Decimal('95.0')
        )
        
        self.assertEqual(price_data.symbol, "BTC/USD")
        self.assertEqual(price_data.price, Decimal('50000.00'))
        self.assertFalse(price_data.is_stale)  # Should be fresh
        
    def test_add_data_source(self):
        """Test adding data source to manager"""
        source = DataSource(
            source_id="test_source",
            name="Test Source",
            url="https://test.com",
            api_key="",
            is_active=True,
            reliability_score=90.0,
            supported_pairs=["BTC/USD"]
        )
        
        success = self.price_manager.add_data_source(source)
        self.assertTrue(success)
        self.assertIn("test_source", self.price_manager.data_sources)
        
    def test_add_oracle_node(self):
        """Test adding oracle node to manager"""
        node = OracleNode(
            node_id="test_oracle",
            address="0x123",
            public_key="public_key",
            reputation=Decimal('90.0'),
            stake_amount=50000,
            is_active=True,
            last_update=int(time.time()),
            total_updates=50,
            successful_updates=45,
            failed_updates=5,
            supported_pairs=["BTC/USD"]
        )
        
        success = self.price_manager.add_oracle_node(node)
        self.assertTrue(success)
        self.assertIn("test_oracle", self.price_manager.oracle_nodes)
        
    @patch('requests.get')
    def test_fetch_price_data(self, mock_get):
        """Test fetching price data from external source"""
        # Mock API response
        mock_response = Mock()
        mock_response.json.return_value = {
            'symbol': 'BTCUSDT',
            'price': '50000.00',
            'volume': '1000.0'
        }
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        # Add data source
        source = DataSource(
            source_id="binance",
            name="Binance",
            url="https://api.binance.com",
            api_key="",
            is_active=True,
            reliability_score=95.0,
            supported_pairs=["BTC/USD"]
        )
        self.price_manager.add_data_source(source)
        
        # Fetch price data
        price_data = self.price_manager.fetch_price_data("binance", "BTC/USD")
        
        self.assertIsNotNone(price_data)
        self.assertEqual(price_data.symbol, "BTC/USD")
        
    def test_price_aggregation(self):
        """Test price aggregation from multiple sources"""
        # Create sample price data
        prices = [
            PriceData("BTC/USD", Decimal('50000'), int(time.time()), "source1", Decimal('100'), Decimal('95')),
            PriceData("BTC/USD", Decimal('50100'), int(time.time()), "source2", Decimal('200'), Decimal('90')),
            PriceData("BTC/USD", Decimal('49900'), int(time.time()), "source3", Decimal('150'), Decimal('85'))
        ]
        
        # Test median aggregation
        aggregated = self.price_manager.aggregate_prices(
            prices, AggregationMethod.MEDIAN
        )
        
        self.assertIsInstance(aggregated, AggregatedPrice)
        self.assertEqual(aggregated.price, Decimal('50000'))  # Median price
        self.assertEqual(aggregated.source_count, 3)
        
        # Test weighted average
        weighted_avg = self.price_manager.aggregate_prices(
            prices, AggregationMethod.VOLUME_WEIGHTED_AVERAGE
        )
        
        self.assertIsInstance(weighted_avg, AggregatedPrice)
        self.assertGreater(weighted_avg.price, Decimal('49900'))
        self.assertLess(weighted_avg.price, Decimal('50100'))

class TestOracleManager(unittest.TestCase):
    """Test cases for oracle management system"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.oracle_manager = OracleManager(min_stake_amount=10000)
        
    def test_oracle_registration(self):
        """Test oracle registration"""
        oracle_address = "0x123"
        public_key = ECDSAKeyPair.generate().export_public_key()
        stake_amount = 50000
        supported_types = [OracleType.PRICE_FEED, OracleType.WEATHER]
        
        oracle_id = self.oracle_manager.register_oracle(
            oracle_address, public_key, stake_amount, supported_types
        )
        
        self.assertIsNotNone(oracle_id)
        self.assertIn(oracle_id, self.oracle_manager.oracle_nodes)
        
        oracle = self.oracle_manager.oracle_nodes[oracle_id]
        self.assertEqual(oracle.address, oracle_address)
        self.assertEqual(oracle.stake_amount, stake_amount)
        
    def test_oracle_registration_insufficient_stake(self):
        """Test oracle registration with insufficient stake"""
        oracle_address = "0x123"
        public_key = ECDSAKeyPair.generate().export_public_key()
        stake_amount = 5000  # Below minimum
        supported_types = [OracleType.PRICE_FEED]
        
        with self.assertRaises(ValueError):
            self.oracle_manager.register_oracle(
                oracle_address, public_key, stake_amount, supported_types
            )
            
    def test_data_request_creation(self):
        """Test data request creation"""
        # First register an oracle
        oracle_address = "0x123"
        public_key = ECDSAKeyPair.generate().export_public_key()
        stake_amount = 50000
        supported_types = [OracleType.PRICE_FEED]
        
        oracle_id = self.oracle_manager.register_oracle(
            oracle_address, public_key, stake_amount, supported_types
        )
        
        # Create data request
        requester = "0x456"
        oracle_type = OracleType.PRICE_FEED
        data_spec = {'symbol': 'BTC/USD'}
        reward_amount = 1000
        
        request_id = self.oracle_manager.create_data_request(
            requester, oracle_type, data_spec, reward_amount
        )
        
        self.assertIsNotNone(request_id)
        self.assertIn(request_id, self.oracle_manager.data_requests)
        
        request = self.oracle_manager.data_requests[request_id]
        self.assertEqual(request.requester, requester)
        self.assertEqual(request.oracle_type, oracle_type)
        self.assertEqual(request.reward_amount, reward_amount)
        
    def test_oracle_response_submission(self):
        """Test oracle response submission"""
        # Setup oracle and request
        key_pair = ECDSAKeyPair.generate()
        oracle_address = "0x123"
        public_key = key_pair.export_public_key()
        stake_amount = 50000
        supported_types = [OracleType.PRICE_FEED]
        
        oracle_id = self.oracle_manager.register_oracle(
            oracle_address, public_key, stake_amount, supported_types
        )
        
        request_id = self.oracle_manager.create_data_request(
            "0x456", OracleType.PRICE_FEED, {'symbol': 'BTC/USD'}, 1000
        )
        
        # Submit response
        response_data = {'price': '50000.00'}
        confidence = Decimal('95.0')
        private_key = key_pair.private_key.hex()
        
        response_id = self.oracle_manager.submit_oracle_response(
            oracle_id, request_id, response_data, confidence, private_key
        )
        
        self.assertIsNotNone(response_id)
        self.assertIn(response_id, self.oracle_manager.oracle_responses)
        
        response = self.oracle_manager.oracle_responses[response_id]
        self.assertEqual(response.oracle_id, oracle_id)
        self.assertEqual(response.request_id, request_id)
        self.assertEqual(response.data, response_data)
        
    def test_dispute_creation(self):
        """Test dispute creation"""
        # Setup oracle, request, and response
        key_pair = ECDSAKeyPair.generate()
        oracle_address = "0x123"
        public_key = key_pair.export_public_key()
        stake_amount = 50000
        
        oracle_id = self.oracle_manager.register_oracle(
            oracle_address, public_key, stake_amount, [OracleType.PRICE_FEED]
        )
        
        request_id = self.oracle_manager.create_data_request(
            "0x456", OracleType.PRICE_FEED, {'symbol': 'BTC/USD'}, 1000
        )
        
        response_id = self.oracle_manager.submit_oracle_response(
            oracle_id, request_id, {'price': '50000.00'}, Decimal('95.0'), key_pair.private_key.hex()
        )
        
        # Create dispute
        challenger = "0x789"
        reason = "Incorrect price data"
        evidence = {'correct_price': '49000.00'}
        stake_amount = 5000  # 10% of oracle stake
        
        dispute_id = self.oracle_manager.create_dispute(
            challenger, request_id, response_id, reason, evidence, stake_amount
        )
        
        self.assertIsNotNone(dispute_id)
        self.assertIn(dispute_id, self.oracle_manager.disputes)
        
        dispute = self.oracle_manager.disputes[dispute_id]
        self.assertEqual(dispute.challenger, challenger)
        self.assertEqual(dispute.reason, reason)
        self.assertEqual(dispute.status, DisputeStatus.OPEN)

class TestWallet(unittest.TestCase):
    """Test cases for wallet system"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.wallet = Wallet("test_wallet_001")
        
    def test_wallet_creation(self):
        """Test basic wallet creation"""
        self.assertIsNotNone(self.wallet.wallet_id)
        self.assertEqual(self.wallet.wallet_id, "test_wallet_001")
        self.assertEqual(len(self.wallet.accounts), 0)
        
    def test_account_creation(self):
        """Test account creation in wallet"""
        # Initialize HD wallet first
        self.wallet.initialize_hd_wallet()
        account_id = self.wallet.create_account("Main Account")
        
        self.assertIsNotNone(account_id)
        
        # Get account info to verify creation
        account_info = self.wallet.get_account_info(account_id)
        self.assertIsNotNone(account_info)
        self.assertEqual(account_info['name'], "Main Account")
        self.assertIsNotNone(account_info['address'])
        self.assertEqual(len(self.wallet.accounts), 1)
        
    def test_hd_wallet_creation(self):
        """Test HD wallet creation"""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        hd_wallet = HDWallet(mnemonic)
        
        self.assertIsNotNone(hd_wallet)
        self.assertEqual(hd_wallet.mnemonic, mnemonic)
        
        # Derive keys using available method
        key1 = hd_wallet.derive_key("m/44'/0'/0'/0/0")
        key2 = hd_wallet.derive_key("m/44'/0'/0'/0/1")
        
        self.assertNotEqual(key1.private_key, key2.private_key)
        self.assertNotEqual(key1.public_key, key2.public_key)
        
    def test_multisig_wallet_creation(self):
        """Test multi-signature wallet creation"""
        # Create multiple key pairs
        key_pairs = [ECDSAKeyPair.generate() for _ in range(3)]
        public_keys = [kp.export_public_key() for kp in key_pairs]
        
        # Initialize HD wallet first
        self.wallet.initialize_hd_wallet()
        
        # Create multisig account using the available method
        account_id = self.wallet.create_multisig_account(
            name="Test MultiSig",
            required_signatures=2,
            signer_public_keys=public_keys
        )
        
        self.assertIsNotNone(account_id)
        account = self.wallet.accounts.get(account_id)
        self.assertIsNotNone(account)
        self.assertEqual(account.name, "Test MultiSig")

class TestAccountManager(unittest.TestCase):
    """Test cases for account management system"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.account_manager = AccountManager("test_secret_key")
        
    def test_user_registration(self):
        """Test user registration"""
        username = "testuser"
        email = "test@example.com"
        password = "secure_password_123"
        
        user_id = self.account_manager.register_user(username, email, password)
        
        self.assertIsNotNone(user_id)
        self.assertIn(user_id, self.account_manager.users)
        
        user = self.account_manager.users[user_id]
        self.assertEqual(user.username, username)
        self.assertEqual(user.email, email)
        
    def test_user_authentication(self):
        """Test user authentication"""
        username = "testuser"
        email = "test@example.com"
        password = "secure_password_123"
        
        user_id = self.account_manager.register_user(username, email, password)
        
        # Test successful login
        session_token = self.account_manager.authenticate_user(username, password)
        self.assertIsNotNone(session_token)
        
        # Test failed login
        failed_token = self.account_manager.authenticate_user(username, "wrong_password")
        self.assertIsNone(failed_token)
        
    def test_permission_management(self):
        """Test permission management"""
        username = "testuser"
        email = "test@example.com"
        password = "secure_password_123"
        
        user_id = self.account_manager.register_user(username, email, password)
        
        # Grant permission
        success = self.account_manager.grant_permission(
            user_id, PermissionType.TRADE
        )
        self.assertTrue(success)
        
        # Check permission
        has_permission = self.account_manager.has_permission(
            user_id, PermissionType.TRADE
        )
        self.assertTrue(has_permission)
        
        # Revoke permission
        success = self.account_manager.revoke_permission(
            user_id, PermissionType.TRADE
        )
        self.assertTrue(success)
        
        # Check permission again
        has_permission = self.account_manager.has_permission(
            user_id, PermissionType.TRADE
        )
        self.assertFalse(has_permission)

if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_suite.addTest(unittest.makeSuite(TestCryptography))
    test_suite.addTest(unittest.makeSuite(TestSignatures))
    test_suite.addTest(unittest.makeSuite(TestPriceFeed))
    test_suite.addTest(unittest.makeSuite(TestOracleManager))
    test_suite.addTest(unittest.makeSuite(TestWallet))
    test_suite.addTest(unittest.makeSuite(TestAccountManager))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    print(f"\n{'='*50}")
    print(f"Security & Oracle Tests Summary")
    print(f"{'='*50}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    print(f"{'='*50}")