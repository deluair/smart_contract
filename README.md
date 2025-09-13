# Smart Contract Financial Ecosystem

A comprehensive blockchain-based financial ecosystem with smart contracts, decentralized exchange, lending protocols, derivatives trading, and advanced security features.

## 🚀 Features

### Core Blockchain
- **Transaction Management**: Secure transaction creation, validation, and processing
- **Block Management**: Efficient block creation with Merkle tree validation
- **Proof of Stake Consensus**: Energy-efficient consensus mechanism with validator staking
- **Smart Contract Engine**: Full-featured virtual machine for contract execution
- **P2P Network Layer**: Decentralized peer-to-peer communication with node discovery
- **REST API**: Comprehensive HTTP API for blockchain interaction

### Financial Smart Contracts
- **ERC-20 Token**: Feature-rich token with minting, burning, staking, and dividends
- **Decentralized Exchange (DEX)**: Automated market maker with liquidity pools
- **Lending Protocol**: Collateralized lending with dynamic interest rates
- **Derivatives Trading**: Options, futures, and swaps with margin management

### Security & Cryptography
- **ECDSA Key Management**: Secure key generation and digital signatures
- **Multi-signature Wallets**: Enhanced security with threshold signatures
- **Encryption/Decryption**: AES-256 encryption for sensitive data
- **Hash Functions**: SHA-256, SHA-3, and BLAKE2b support

### Oracle System
- **Price Feeds**: Real-time market data from multiple sources
- **Oracle Management**: Decentralized oracle network with reputation system
- **Data Validation**: Consensus-based data verification and dispute resolution
- **Multi-source Aggregation**: Median and volume-weighted price calculations

### Wallet & Account Management
- **HD Wallets**: Hierarchical deterministic wallet support
- **Account Management**: User authentication with 2FA and role-based permissions
- **Session Management**: Secure session handling with token-based authentication
- **Multi-signature Support**: Enterprise-grade wallet security

### Network & Infrastructure
- **P2P Communication**: Peer-to-peer messaging and data synchronization
- **Node Discovery**: Automatic peer discovery and network bootstrapping
- **Message Handling**: Efficient network message processing and routing
- **Protocol Management**: Standardized network communication protocols

### API & Web Interface
- **REST API**: Full-featured HTTP API with authentication and rate limiting
- **Web Interface**: Modern web-based user interface for blockchain interaction
- **Documentation**: Comprehensive API documentation and deployment guides
- **Deployment Scripts**: Automated deployment and configuration tools

## 📁 Project Structure

```
smart_contract/
├── api/
│   ├── __init__.py
│   └── rest_api.py          # REST API implementation
├── blockchain/
│   ├── core/
│   │   ├── transaction.py      # Transaction management
│   │   ├── block.py           # Block structure and validation
│   │   └── blockchain.py      # Main blockchain implementation
│   ├── consensus/
│   │   ├── __init__.py
│   │   └── pos.py            # Proof of Stake consensus
│   └── network/
│       ├── __init__.py
│       ├── network_manager.py  # P2P network management
│       ├── peer_manager.py     # Peer connection management
│       ├── message_handler.py  # Network message processing
│       ├── node_discovery.py   # Node discovery protocol
│       └── protocol.py         # Network protocol definitions
├── smart_contracts/
│   ├── engine/
│   │   ├── __init__.py
│   │   ├── engine.py         # Smart contract engine
│   │   └── vm.py            # Virtual machine
│   └── financial/
│       ├── __init__.py
│       ├── token.py          # ERC-20 token implementation
│       ├── dex.py           # Decentralized exchange
│       ├── lending.py       # Lending protocol
│       └── derivatives.py   # Derivatives trading
├── security/
│   ├── __init__.py
│   ├── cryptography.py      # Cryptographic functions
│   └── signatures.py       # Digital signature management
├── oracles/
│   ├── __init__.py
│   ├── price_feed.py       # Price feed management
│   └── oracle_manager.py   # Oracle network management
├── wallet/
│   ├── __init__.py
│   ├── wallet.py           # Wallet implementation
│   └── account_manager.py  # Account management
├── docs/
│   ├── API_DOCUMENTATION.md    # Comprehensive API documentation
│   └── DEPLOYMENT_GUIDE.md     # Deployment instructions
├── scripts/
│   └── deploy.sh              # Automated deployment script
├── web/
│   ├── index.html            # Web interface
│   ├── app.js               # Frontend JavaScript
│   └── styles.css           # Styling
├── tests/
│   ├── test_blockchain.py       # Blockchain tests
│   ├── test_smart_contracts.py  # Smart contract tests
│   └── test_security_oracles.py # Security and oracle tests
├── main.py                 # Main application entry point
├── requirements.txt        # Python dependencies
└── README.md              # This file
```

## 🛠️ Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/deluair/smart_contract.git
   cd smart_contract
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run tests**
   ```bash
   python -m pytest tests/ -v
   ```

4. **Start the application**
   ```bash
   # Start full blockchain platform
   python main.py
   
   # Start API server only
   python main.py --api-only --port 8080
   
   # Start blockchain node only
   python main.py --blockchain-only
   
   # Start oracle service only
   python main.py --oracle-only
   ```

## 🚀 Quick Start

### 1. Initialize Blockchain

```python
from blockchain.core import Blockchain
from blockchain.consensus import create_pos_consensus

# Create blockchain with PoS consensus
consensus = create_pos_consensus()
blockchain = Blockchain(consensus_mechanism=consensus)

print(f"Genesis block hash: {blockchain.get_latest_block().hash}")
```

### 2. Deploy Smart Contracts

```python
from smart_contracts.financial import (
    ERC20Token, DecentralizedExchange, LendingProtocol
)

# Deploy ERC-20 token
token = ERC20Token(
    name="MyToken",
    symbol="MTK",
    total_supply=1000000,
    decimals=18
)

# Deploy DEX
dex = DecentralizedExchange()
dex.add_trading_pair("MTK", "ETH")

# Deploy lending protocol
lending = LendingProtocol()
lending.add_supported_asset("MTK", ltv_ratio=0.75)
```

### 3. Create and Manage Wallets

```python
from wallet import Wallet, HDWallet, AccountManager

# Create HD wallet
mnemonic = HDWallet.generate_mnemonic()
hd_wallet = HDWallet.from_mnemonic(mnemonic)

# Derive accounts
account1 = hd_wallet.derive_account(0)
account2 = hd_wallet.derive_account(1)

print(f"Account 1 address: {account1.address}")
print(f"Account 2 address: {account2.address}")
```

### 4. Set Up Oracle System

```python
from oracles import PriceFeedManager, OracleManager

# Initialize price feed manager
price_manager = PriceFeedManager()

# Add data sources
from oracles.price_feed import DataSource
binance_source = DataSource(
    source_id="binance",
    name="Binance",
    url="https://api.binance.com",
    supported_pairs=["BTC/USD", "ETH/USD"]
)
price_manager.add_data_source(binance_source)

# Fetch price data
btc_price = price_manager.get_latest_price("BTC/USD")
print(f"BTC Price: ${btc_price.price}")
```

## 📊 API Reference

### Blockchain Core

#### Transaction
```python
from blockchain.core import Transaction

# Create transaction
tx = Transaction(
    sender="0x123...",
    recipient="0x456...",
    amount=100,
    fee=1
)

# Sign transaction
tx.sign(private_key)

# Validate transaction
is_valid = tx.validate()
```

#### Block
```python
from blockchain.core import Block

# Create block
block = Block(
    index=1,
    transactions=[tx1, tx2, tx3],
    previous_hash="0x789...",
    validator="0xabc..."
)

# Mine block
block.mine(difficulty=4)
```

### Smart Contracts

#### ERC-20 Token
```python
from smart_contracts.financial import ERC20Token

token = ERC20Token("MyToken", "MTK", 1000000)

# Transfer tokens
token.transfer("0x123...", "0x456...", 100)

# Approve spending
token.approve("0x123...", "0x789...", 50)

# Check balance
balance = token.balance_of("0x123...")
```

#### Decentralized Exchange
```python
from smart_contracts.financial import DecentralizedExchange

dex = DecentralizedExchange()

# Add liquidity
dex.add_liquidity("ETH", "USDC", 10, 30000)

# Execute swap
dex.swap("ETH", "USDC", 1, min_output=2900)

# Get price
price = dex.get_price("ETH", "USDC")
```

#### Lending Protocol
```python
from smart_contracts.financial import LendingProtocol

lending = LendingProtocol()

# Supply collateral
lending.supply("0x123...", "ETH", 5)

# Borrow against collateral
lending.borrow("0x123...", "USDC", 10000)

# Repay loan
lending.repay("0x123...", "USDC", 5000)
```

### Oracle System

#### Price Feed
```python
from oracles import PriceFeedManager

manager = PriceFeedManager()

# Get latest price
price = manager.get_latest_price("BTC/USD")

# Get historical prices
history = manager.get_price_history("BTC/USD", hours=24)

# Subscribe to price updates
manager.subscribe_to_updates("ETH/USD", callback_function)
```

#### Oracle Management
```python
from oracles import OracleManager

oracle_mgr = OracleManager()

# Register oracle
oracle_id = oracle_mgr.register_oracle(
    address="0x123...",
    public_key="0x456...",
    stake_amount=50000
)

# Create data request
request_id = oracle_mgr.create_data_request(
    requester="0x789...",
    oracle_type="PRICE_FEED",
    data_spec={"symbol": "BTC/USD"},
    reward=1000
)
```

## 🧪 Testing

The project includes comprehensive test suites:

### Run All Tests
```bash
python -m pytest tests/ -v
```

### Run Specific Test Modules
```bash
# Blockchain tests
python tests/test_blockchain.py

# Smart contract tests
python tests/test_smart_contracts.py

# Security and oracle tests
python tests/test_security_oracles.py
```

### Test Coverage
- **Blockchain Core**: Transaction validation, block mining, consensus
- **Smart Contracts**: Token operations, DEX functionality, lending
- **Security**: Cryptography, signatures, multi-sig wallets
- **Oracles**: Price feeds, data validation, dispute resolution
- **Wallets**: HD wallets, account management, authentication

## 🔒 Security Features

### Cryptographic Security
- **ECDSA Signatures**: Secure transaction signing with secp256k1
- **AES-256 Encryption**: Industry-standard symmetric encryption
- **Secure Random Generation**: Cryptographically secure randomness
- **Hash Functions**: Multiple hash algorithms for different use cases

### Multi-signature Support
- **Threshold Signatures**: M-of-N signature schemes
- **Transaction Proposals**: Collaborative transaction creation
- **Signature Aggregation**: Efficient signature verification

### Access Control
- **Role-based Permissions**: Granular access control system
- **Two-factor Authentication**: Enhanced account security
- **Session Management**: Secure token-based authentication

## 🌐 Oracle Network

### Price Feed Sources
- **Binance API**: Real-time cryptocurrency prices
- **Coinbase Pro**: Professional trading data
- **Kraken API**: European market data
- **Custom Sources**: Extensible data source framework

### Data Validation
- **Consensus Mechanisms**: Multiple oracle validation
- **Reputation System**: Oracle performance tracking
- **Dispute Resolution**: Challenge incorrect data submissions
- **Slashing Conditions**: Penalties for malicious behavior

## 🏗️ Architecture

### Design Principles
- **Modularity**: Loosely coupled components
- **Extensibility**: Plugin-based architecture
- **Security**: Defense in depth approach
- **Performance**: Optimized for high throughput
- **Scalability**: Horizontal scaling support

### Key Components
1. **Blockchain Layer**: Core consensus and transaction processing
2. **Smart Contract Layer**: Programmable business logic
3. **Security Layer**: Cryptographic primitives and access control
4. **Oracle Layer**: External data integration
5. **Application Layer**: User interfaces and APIs

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Install development dependencies
4. Make your changes
5. Run tests
6. Submit a pull request

### Code Style
- Follow PEP 8 guidelines
- Use type hints where appropriate
- Write comprehensive docstrings
- Include unit tests for new features

### Testing Guidelines
- Maintain >90% test coverage
- Test both success and failure cases
- Use mocking for external dependencies
- Include integration tests

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- **Ethereum Foundation**: For ERC-20 standard inspiration
- **Bitcoin Core**: For blockchain architecture concepts
- **Chainlink**: For oracle network design patterns
- **OpenZeppelin**: For smart contract security best practices

## 📚 Documentation

Comprehensive documentation is available in the `docs/` directory:

- **[API Documentation](docs/API_DOCUMENTATION.md)**: Complete REST API reference with examples
- **[Deployment Guide](docs/DEPLOYMENT_GUIDE.md)**: Step-by-step deployment instructions for various environments

### Quick Links
- **Repository**: <mcreference link="https://github.com/deluair/smart_contract" index="0">https://github.com/deluair/smart_contract</mcreference>
- **API Server**: http://localhost:8080 (when running with `--api-only`)
- **Web Interface**: Available in the `web/` directory

## 🚀 Deployment

Use the automated deployment script for easy setup:

```bash
# Make script executable
chmod +x scripts/deploy.sh

# Run deployment
./scripts/deploy.sh
```

For detailed deployment instructions, see the [Deployment Guide](docs/DEPLOYMENT_GUIDE.md).

## 📞 Support

For questions, issues, or contributions:
- Create an issue on GitHub: <mcreference link="https://github.com/deluair/smart_contract" index="0">https://github.com/deluair/smart_contract</mcreference>
- Contact the development team

---

**Built with ❤️ for the decentralized future**