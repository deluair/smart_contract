from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_restful import Api, Resource
from functools import wraps
import jwt
import time
import logging
from decimal import Decimal
from typing import Dict, Any, Optional, List

# Import our blockchain and smart contract modules
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blockchain import Blockchain, Transaction, Block, ProofOfStakeConsensus
from smart_contracts.financial import (
    ERC20Token, DecentralizedExchange, LendingProtocol, DerivativesExchange
)
from wallet import Wallet, HDWallet, AccountManager
from oracles import PriceFeedManager, OracleManager
from security.cryptography import ECDSAKeyPair, CryptoUtils
from security.signatures import TransactionSigner, SignatureValidator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BlockchainAPI:
    """Main API class for the blockchain financial ecosystem"""
    
    def __init__(self):
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
        
        # Enable CORS for all routes
        CORS(self.app)
        
        # Initialize Flask-RESTful
        self.api = Api(self.app)
        
        # Initialize core components
        self.blockchain = None
        self.consensus = None
        self.account_manager = AccountManager("api_secret_key_placeholder")
        self.price_manager = PriceFeedManager()
        self.oracle_manager = OracleManager()
        self.crypto_utils = CryptoUtils()
        self.signature_validator = SignatureValidator()
        
        # Smart contract instances
        self.deployed_contracts = {}
        
        # Initialize blockchain
        self._initialize_blockchain()
        
        # Register API routes
        self._register_routes()
        
    def _initialize_blockchain(self):
        """Initialize the blockchain with PoS consensus"""
        try:
            self.consensus = ProofOfStakeConsensus()
            self.blockchain = Blockchain()
            logger.info("Blockchain initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize blockchain: {e}")
            raise
            
    def _register_routes(self):
        """Register all API routes"""
        # Authentication routes
        self.api.add_resource(AuthResource, '/api/auth/login', 
                             resource_class_kwargs={'api': self})
        self.api.add_resource(RegisterResource, '/api/auth/register',
                             resource_class_kwargs={'api': self})
        
        # Blockchain routes
        self.api.add_resource(BlockchainInfoResource, '/api/blockchain/info',
                             resource_class_kwargs={'api': self})
        self.api.add_resource(TransactionResource, '/api/blockchain/transaction',
                             resource_class_kwargs={'api': self})
        self.api.add_resource(BlockResource, '/api/blockchain/block/<int:block_id>',
                             resource_class_kwargs={'api': self})
        
        # Wallet routes
        self.api.add_resource(WalletResource, '/api/wallet',
                             resource_class_kwargs={'api': self})
        self.api.add_resource(BalanceResource, '/api/wallet/balance/<address>',
                             resource_class_kwargs={'api': self})
        
        # Smart contract routes
        self.api.add_resource(TokenResource, '/api/contracts/token',
                             resource_class_kwargs={'api': self})
        self.api.add_resource(DEXResource, '/api/contracts/dex',
                             resource_class_kwargs={'api': self})
        self.api.add_resource(LendingResource, '/api/contracts/lending',
                             resource_class_kwargs={'api': self})
        self.api.add_resource(DerivativesResource, '/api/contracts/derivatives',
                             resource_class_kwargs={'api': self})
        
        # Oracle routes
        self.api.add_resource(PriceFeedResource, '/api/oracle/price/<symbol>',
                             resource_class_kwargs={'api': self})
        self.api.add_resource(OracleResource, '/api/oracle',
                             resource_class_kwargs={'api': self})
        
        # Market data routes
        self.api.add_resource(MarketDataResource, '/api/market/data',
                             resource_class_kwargs={'api': self})
        
    def run(self, host='0.0.0.0', port=5000, debug=False):
        """Run the Flask application"""
        logger.info(f"Starting API server on {host}:{port}")
        self.app.run(host=host, port=port, debug=debug)

def require_auth(f):
    """Decorator to require authentication for API endpoints"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return {'error': 'No authorization token provided'}, 401
            
        try:
            # Remove 'Bearer ' prefix if present
            if token.startswith('Bearer '):
                token = token[7:]
                
            # Decode JWT token
            payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            g.current_user_id = payload['user_id']
            
        except jwt.ExpiredSignatureError:
            return {'error': 'Token has expired'}, 401
        except jwt.InvalidTokenError:
            return {'error': 'Invalid token'}, 401
            
        return f(*args, **kwargs)
    return decorated_function

class AuthResource(Resource):
    """Authentication endpoints"""
    
    def __init__(self, api):
        self.api = api
        
    def post(self):
        """User login"""
        try:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            
            if not username or not password:
                return {'error': 'Username and password required'}, 400
                
            # Authenticate user
            session_token = self.api.account_manager.authenticate_user(username, password)
            
            if session_token:
                # Create JWT token
                payload = {
                    'user_id': username,
                    'exp': int(time.time()) + 3600  # 1 hour expiration
                }
                jwt_token = jwt.encode(payload, self.api.app.config['SECRET_KEY'], algorithm='HS256')
                
                return {
                    'success': True,
                    'token': jwt_token,
                    'session_token': session_token
                }
            else:
                return {'error': 'Invalid credentials'}, 401
                
        except Exception as e:
            logger.error(f"Login error: {e}")
            return {'error': 'Internal server error'}, 500

class RegisterResource(Resource):
    """User registration endpoint"""
    
    def __init__(self, api):
        self.api = api
        
    def post(self):
        """Register new user"""
        try:
            data = request.get_json()
            username = data.get('username')
            email = data.get('email')
            password = data.get('password')
            
            if not all([username, email, password]):
                return {'error': 'Username, email, and password required'}, 400
                
            # Register user
            user_id = self.api.account_manager.register_user(username, email, password)
            
            if user_id:
                return {
                    'success': True,
                    'user_id': user_id,
                    'message': 'User registered successfully'
                }
            else:
                return {'error': 'Registration failed'}, 400
                
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return {'error': 'Internal server error'}, 500

class BlockchainInfoResource(Resource):
    """Blockchain information endpoints"""
    
    def __init__(self, api):
        self.api = api
        
    def get(self):
        """Get blockchain information"""
        try:
            latest_block = self.api.blockchain.get_latest_block()
            
            return {
                'chain_length': len(self.api.blockchain.chain),
                'latest_block': {
                    'index': latest_block.index,
                    'hash': latest_block.hash,
                    'timestamp': latest_block.timestamp,
                    'transaction_count': len(latest_block.transactions)
                },
                'total_transactions': sum(len(block.transactions) for block in self.api.blockchain.chain),
                'consensus_type': 'Proof of Stake',
                'network_status': 'active'
            }
            
        except Exception as e:
            logger.error(f"Blockchain info error: {e}")
            return {'error': 'Failed to get blockchain info'}, 500

class TransactionResource(Resource):
    """Transaction management endpoints"""
    
    def __init__(self, api):
        self.api = api
        
    @require_auth
    def post(self):
        """Create and submit a new transaction"""
        try:
            data = request.get_json()
            
            # Validate required fields
            required_fields = ['sender', 'recipient', 'amount', 'private_key']
            if not all(field in data for field in required_fields):
                return {'error': 'Missing required fields'}, 400
                
            # Create transaction
            transaction = Transaction(
                sender=data['sender'],
                recipient=data['recipient'],
                amount=Decimal(str(data['amount'])),
                fee=Decimal(str(data.get('fee', '0.001'))),
                data=data.get('data', '')
            )
            
            # Sign transaction
            private_key = data['private_key']
            transaction.sign(private_key)
            
            # Validate transaction
            if not transaction.validate():
                return {'error': 'Invalid transaction'}, 400
                
            # Add to blockchain
            success = self.api.blockchain.add_transaction(transaction)
            
            if success:
                return {
                    'success': True,
                    'transaction_id': transaction.transaction_id,
                    'hash': transaction.hash
                }
            else:
                return {'error': 'Failed to add transaction'}, 400
                
        except Exception as e:
            logger.error(f"Transaction creation error: {e}")
            return {'error': 'Failed to create transaction'}, 500
            
    def get(self):
        """Get transaction by ID"""
        try:
            tx_id = request.args.get('id')
            if not tx_id:
                return {'error': 'Transaction ID required'}, 400
                
            # Search for transaction in blockchain
            for block in self.api.blockchain.chain:
                for tx in block.transactions:
                    if tx.transaction_id == tx_id:
                        return {
                            'transaction_id': tx.transaction_id,
                            'sender': tx.sender,
                            'recipient': tx.recipient,
                            'amount': str(tx.amount),
                            'fee': str(tx.fee),
                            'timestamp': tx.timestamp,
                            'hash': tx.hash,
                            'block_index': block.index
                        }
                        
            return {'error': 'Transaction not found'}, 404
            
        except Exception as e:
            logger.error(f"Transaction retrieval error: {e}")
            return {'error': 'Failed to retrieve transaction'}, 500

class BlockResource(Resource):
    """Block information endpoints"""
    
    def __init__(self, api):
        self.api = api
        
    def get(self, block_id):
        """Get block by index"""
        try:
            if block_id >= len(self.api.blockchain.chain) or block_id < 0:
                return {'error': 'Block not found'}, 404
                
            block = self.api.blockchain.chain[block_id]
            
            return {
                'index': block.index,
                'hash': block.hash,
                'previous_hash': block.previous_hash,
                'timestamp': block.timestamp,
                'validator': block.validator,
                'merkle_root': block.merkle_root,
                'transaction_count': len(block.transactions),
                'transactions': [
                    {
                        'id': tx.transaction_id,
                        'sender': tx.sender,
                        'recipient': tx.recipient,
                        'amount': str(tx.amount),
                        'fee': str(tx.fee)
                    } for tx in block.transactions
                ]
            }
            
        except Exception as e:
            logger.error(f"Block retrieval error: {e}")
            return {'error': 'Failed to retrieve block'}, 500

class WalletResource(Resource):
    """Wallet management endpoints"""
    
    def __init__(self, api):
        self.api = api
        
    @require_auth
    def post(self):
        """Create a new wallet"""
        try:
            data = request.get_json()
            wallet_type = data.get('type', 'standard')  # standard, hd, multisig
            
            if wallet_type == 'hd':
                # Create HD wallet
                mnemonic = HDWallet.generate_mnemonic()
                hd_wallet = HDWallet.from_mnemonic(mnemonic)
                account = hd_wallet.derive_account(0)
                
                return {
                    'success': True,
                    'wallet_type': 'hd',
                    'mnemonic': mnemonic,
                    'address': account.address,
                    'public_key': account.public_key.hex()
                }
                
            elif wallet_type == 'multisig':
                # Create multisig wallet
                required_signatures = data.get('required_signatures', 2)
                public_keys = data.get('public_keys', [])
                
                if len(public_keys) < required_signatures:
                    return {'error': 'Not enough public keys for required signatures'}, 400
                    
                wallet = Wallet()
                multisig_config = {
                    'public_keys': public_keys,
                    'required_signatures': required_signatures,
                    'wallet_type': f"{required_signatures}-of-{len(public_keys)}"
                }
                
                multisig_wallet = wallet.create_multisig_wallet(multisig_config)
                
                return {
                    'success': True,
                    'wallet_type': 'multisig',
                    'address': multisig_wallet.address,
                    'required_signatures': required_signatures,
                    'total_keys': len(public_keys)
                }
                
            else:
                # Create standard wallet
                key_pair = ECDSAKeyPair.generate()
                
                return {
                    'success': True,
                    'wallet_type': 'standard',
                    'address': key_pair.get_address(),
                    'public_key': key_pair.public_key.hex(),
                    'private_key': key_pair.private_key.hex()  # In production, encrypt this!
                }
                
        except Exception as e:
            logger.error(f"Wallet creation error: {e}")
            return {'error': 'Failed to create wallet'}, 500

class BalanceResource(Resource):
    """Balance query endpoints"""
    
    def __init__(self, api):
        self.api = api
        
    def get(self, address):
        """Get balance for an address"""
        try:
            balance = self.api.blockchain.get_balance(address)
            
            return {
                'address': address,
                'balance': str(balance),
                'currency': 'native_token'
            }
            
        except Exception as e:
            logger.error(f"Balance query error: {e}")
            return {'error': 'Failed to get balance'}, 500

class TokenResource(Resource):
    """ERC-20 token contract endpoints"""
    
    def __init__(self, api):
        self.api = api
        
    @require_auth
    def post(self):
        """Deploy a new ERC-20 token"""
        try:
            data = request.get_json()
            
            required_fields = ['name', 'symbol', 'total_supply', 'decimals']
            if not all(field in data for field in required_fields):
                return {'error': 'Missing required fields'}, 400
                
            # Deploy token contract
            token = ERC20Token(
                name=data['name'],
                symbol=data['symbol'],
                total_supply=int(data['total_supply']),
                decimals=int(data['decimals']),
                owner=data.get('owner', g.current_user_id)
            )
            
            # Store contract instance
            contract_address = f"0x{token.contract_id}"
            self.api.deployed_contracts[contract_address] = token
            
            return {
                'success': True,
                'contract_address': contract_address,
                'name': token.name,
                'symbol': token.symbol,
                'total_supply': str(token.total_supply),
                'decimals': token.decimals
            }
            
        except Exception as e:
            logger.error(f"Token deployment error: {e}")
            return {'error': 'Failed to deploy token'}, 500
            
    def get(self):
        """Get token information"""
        try:
            contract_address = request.args.get('address')
            if not contract_address:
                return {'error': 'Contract address required'}, 400
                
            if contract_address not in self.api.deployed_contracts:
                return {'error': 'Contract not found'}, 404
                
            token = self.api.deployed_contracts[contract_address]
            
            return {
                'contract_address': contract_address,
                'name': token.name,
                'symbol': token.symbol,
                'total_supply': str(token.total_supply),
                'decimals': token.decimals,
                'owner': token.owner
            }
            
        except Exception as e:
            logger.error(f"Token info error: {e}")
            return {'error': 'Failed to get token info'}, 500

class DEXResource(Resource):
    """Decentralized Exchange endpoints"""
    
    def __init__(self, api):
        self.api = api
        
    @require_auth
    def post(self):
        """Execute DEX operations"""
        try:
            data = request.get_json()
            operation = data.get('operation')
            
            if operation == 'swap':
                return self._execute_swap(data)
            elif operation == 'add_liquidity':
                return self._add_liquidity(data)
            elif operation == 'remove_liquidity':
                return self._remove_liquidity(data)
            else:
                return {'error': 'Invalid operation'}, 400
                
        except Exception as e:
            logger.error(f"DEX operation error: {e}")
            return {'error': 'DEX operation failed'}, 500
            
    def _execute_swap(self, data):
        """Execute token swap"""
        # Implementation for token swapping
        pass
        
    def _add_liquidity(self, data):
        """Add liquidity to pool"""
        # Implementation for adding liquidity
        pass
        
    def _remove_liquidity(self, data):
        """Remove liquidity from pool"""
        # Implementation for removing liquidity
        pass

class LendingResource(Resource):
    """Lending protocol endpoints"""
    
    def __init__(self, api):
        self.api = api
        
    @require_auth
    def post(self):
        """Execute lending operations"""
        try:
            data = request.get_json()
            operation = data.get('operation')
            
            if operation == 'supply':
                return self._supply_collateral(data)
            elif operation == 'borrow':
                return self._borrow_asset(data)
            elif operation == 'repay':
                return self._repay_loan(data)
            else:
                return {'error': 'Invalid operation'}, 400
                
        except Exception as e:
            logger.error(f"Lending operation error: {e}")
            return {'error': 'Lending operation failed'}, 500
            
    def _supply_collateral(self, data):
        """Supply collateral to lending protocol"""
        # Implementation for supplying collateral
        pass
        
    def _borrow_asset(self, data):
        """Borrow asset against collateral"""
        # Implementation for borrowing
        pass
        
    def _repay_loan(self, data):
        """Repay borrowed amount"""
        # Implementation for loan repayment
        pass

class DerivativesResource(Resource):
    """Derivatives trading endpoints"""
    
    def __init__(self, api):
        self.api = api
        
    @require_auth
    def post(self):
        """Execute derivatives operations"""
        try:
            data = request.get_json()
            operation = data.get('operation')
            
            if operation == 'create_option':
                return self._create_option(data)
            elif operation == 'exercise_option':
                return self._exercise_option(data)
            elif operation == 'create_future':
                return self._create_future(data)
            else:
                return {'error': 'Invalid operation'}, 400
                
        except Exception as e:
            logger.error(f"Derivatives operation error: {e}")
            return {'error': 'Derivatives operation failed'}, 500
            
    def _create_option(self, data):
        """Create options contract"""
        # Implementation for creating options
        pass
        
    def _exercise_option(self, data):
        """Exercise options contract"""
        # Implementation for exercising options
        pass
        
    def _create_future(self, data):
        """Create futures contract"""
        # Implementation for creating futures
        pass

class PriceFeedResource(Resource):
    """Price feed endpoints"""
    
    def __init__(self, api):
        self.api = api
        
    def get(self, symbol):
        """Get latest price for symbol"""
        try:
            price_data = self.api.price_manager.get_latest_price(symbol)
            
            if price_data:
                return {
                    'symbol': price_data.symbol,
                    'price': str(price_data.price),
                    'timestamp': price_data.timestamp,
                    'source': price_data.source,
                    'confidence': str(price_data.confidence)
                }
            else:
                return {'error': 'Price data not available'}, 404
                
        except Exception as e:
            logger.error(f"Price feed error: {e}")
            return {'error': 'Failed to get price data'}, 500

class OracleResource(Resource):
    """Oracle management endpoints"""
    
    def __init__(self, api):
        self.api = api
        
    @require_auth
    def post(self):
        """Register oracle or submit data"""
        try:
            data = request.get_json()
            operation = data.get('operation')
            
            if operation == 'register':
                return self._register_oracle(data)
            elif operation == 'submit_data':
                return self._submit_oracle_data(data)
            else:
                return {'error': 'Invalid operation'}, 400
                
        except Exception as e:
            logger.error(f"Oracle operation error: {e}")
            return {'error': 'Oracle operation failed'}, 500
            
    def _register_oracle(self, data):
        """Register new oracle"""
        # Implementation for oracle registration
        pass
        
    def _submit_oracle_data(self, data):
        """Submit oracle data"""
        # Implementation for data submission
        pass

class MarketDataResource(Resource):
    """Market data endpoints"""
    
    def __init__(self, api):
        self.api = api
        
    def get(self):
        """Get comprehensive market data"""
        try:
            # Get various market metrics
            market_data = {
                'blockchain_stats': {
                    'total_blocks': len(self.api.blockchain.chain),
                    'total_transactions': sum(len(block.transactions) for block in self.api.blockchain.chain),
                    'active_validators': len(self.api.consensus.validators) if self.api.consensus else 0
                },
                'defi_stats': {
                    'total_value_locked': '0',  # Calculate from deployed contracts
                    'active_contracts': len(self.api.deployed_contracts),
                    'trading_volume_24h': '0'  # Calculate from DEX transactions
                },
                'oracle_stats': {
                    'active_oracles': len(self.api.oracle_manager.oracle_nodes),
                    'data_feeds': len(self.api.price_manager.data_sources),
                    'last_update': int(time.time())
                }
            }
            
            return market_data
            
        except Exception as e:
            logger.error(f"Market data error: {e}")
            return {'error': 'Failed to get market data'}, 500

# Main application factory
def create_app():
    """Create and configure the Flask application"""
    api = BlockchainAPI()
    return api.app

if __name__ == '__main__':
    # Create and run the API
    blockchain_api = BlockchainAPI()
    blockchain_api.run(debug=True)