# Smart Contract Platform API Documentation

This document provides comprehensive documentation for the Smart Contract Platform REST API.

## Base URL

```
http://localhost:5000/api
```

## Authentication

The API uses JWT (JSON Web Token) authentication. Include the token in the Authorization header:

```
Authorization: Bearer <your-jwt-token>
```

## Response Format

All API responses follow this standard format:

```json
{
  "success": true|false,
  "data": {},
  "message": "Description of the result",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## Error Codes

| Code | Description |
|------|-------------|
| 200  | Success |
| 400  | Bad Request |
| 401  | Unauthorized |
| 403  | Forbidden |
| 404  | Not Found |
| 500  | Internal Server Error |

## Authentication Endpoints

### POST /auth/login

Authenticate a user and receive a JWT token.

**Request Body:**
```json
{
  "username": "string",
  "password": "string"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "token": "jwt-token-string",
    "expires_in": 3600,
    "user_id": "user-identifier"
  },
  "message": "Login successful"
}
```

### POST /auth/register

Register a new user account.

**Request Body:**
```json
{
  "username": "string",
  "password": "string",
  "email": "string"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "user_id": "user-identifier",
    "username": "string"
  },
  "message": "User registered successfully"
}
```

## Blockchain Endpoints

### GET /blockchain/info

Get blockchain information and statistics.

**Response:**
```json
{
  "success": true,
  "data": {
    "height": 12345,
    "total_transactions": 98765,
    "difficulty": "0x1d00ffff",
    "hash_rate": "1.5 TH/s",
    "latest_block": {
      "hash": "block-hash",
      "timestamp": "2024-01-01T00:00:00Z",
      "transactions": 150
    },
    "network": {
      "peers": 25,
      "version": "1.0.0"
    }
  }
}
```

### POST /blockchain/transaction

Submit a new transaction to the blockchain.

**Request Body:**
```json
{
  "from_address": "sender-address",
  "to_address": "recipient-address",
  "amount": "1.5",
  "gas_limit": 21000,
  "gas_price": "20",
  "data": "optional-transaction-data",
  "signature": "transaction-signature"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "transaction_hash": "tx-hash",
    "status": "pending",
    "gas_used": 21000,
    "block_number": null
  },
  "message": "Transaction submitted successfully"
}
```

### GET /blockchain/transaction

Get recent transactions or search by hash.

**Query Parameters:**
- `hash` (optional): Transaction hash to lookup
- `limit` (optional): Number of transactions to return (default: 10)
- `offset` (optional): Pagination offset (default: 0)

**Response:**
```json
{
  "success": true,
  "data": {
    "transactions": [
      {
        "hash": "tx-hash",
        "from_address": "sender-address",
        "to_address": "recipient-address",
        "amount": "1.5",
        "gas_used": 21000,
        "status": "confirmed",
        "block_number": 12345,
        "timestamp": "2024-01-01T00:00:00Z"
      }
    ],
    "total": 98765,
    "page": 1
  }
}
```

### GET /blockchain/block/{block_id}

Get block information by block number or hash.

**Response:**
```json
{
  "success": true,
  "data": {
    "block": {
      "number": 12345,
      "hash": "block-hash",
      "parent_hash": "parent-block-hash",
      "timestamp": "2024-01-01T00:00:00Z",
      "miner": "miner-address",
      "difficulty": "0x1d00ffff",
      "gas_limit": 8000000,
      "gas_used": 7500000,
      "transactions": [
        {
          "hash": "tx-hash",
          "from_address": "sender",
          "to_address": "recipient",
          "amount": "1.5"
        }
      ]
    }
  }
}
```

## Wallet Endpoints

### POST /wallet

Create a new wallet or perform wallet operations.

**Create Wallet Request:**
```json
{
  "action": "create",
  "wallet_type": "hd",
  "password": "secure-password"
}
```

**Create Wallet Response:**
```json
{
  "success": true,
  "data": {
    "wallet_id": "wallet-identifier",
    "address": "wallet-address",
    "mnemonic": "twelve word mnemonic phrase",
    "public_key": "public-key-hex"
  },
  "message": "Wallet created successfully"
}
```

**Send Transaction Request:**
```json
{
  "action": "send",
  "wallet_id": "wallet-identifier",
  "to_address": "recipient-address",
  "amount": "1.5",
  "password": "wallet-password"
}
```

### GET /wallet/balance/{address}

Get wallet balance for a specific address.

**Response:**
```json
{
  "success": true,
  "data": {
    "address": "wallet-address",
    "balance": "10.5",
    "pending_balance": "0.2",
    "token_balances": {
      "TOKEN1": "100.0",
      "TOKEN2": "50.0"
    }
  }
}
```

## Smart Contract Endpoints

### POST /contracts/token

Deploy or interact with ERC-20 tokens.

**Deploy Token Request:**
```json
{
  "action": "deploy",
  "name": "MyToken",
  "symbol": "MTK",
  "total_supply": "1000000",
  "decimals": 18,
  "owner_address": "owner-address"
}
```

**Transfer Token Request:**
```json
{
  "action": "transfer",
  "contract_address": "token-contract-address",
  "from_address": "sender-address",
  "to_address": "recipient-address",
  "amount": "100.0"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "contract_address": "token-contract-address",
    "transaction_hash": "tx-hash",
    "gas_used": 50000
  },
  "message": "Token operation completed"
}
```

### GET /contracts/token

Get information about deployed tokens.

**Response:**
```json
{
  "success": true,
  "data": {
    "tokens": [
      {
        "address": "token-contract-address",
        "name": "MyToken",
        "symbol": "MTK",
        "total_supply": "1000000",
        "decimals": 18,
        "owner": "owner-address"
      }
    ]
  }
}
```

### POST /contracts/dex

Interact with the Decentralized Exchange.

**Swap Tokens Request:**
```json
{
  "action": "swap",
  "token_in": "token-address-1",
  "token_out": "token-address-2",
  "amount_in": "100.0",
  "min_amount_out": "95.0",
  "user_address": "user-address"
}
```

**Add Liquidity Request:**
```json
{
  "action": "add_liquidity",
  "token_a": "token-address-1",
  "token_b": "token-address-2",
  "amount_a": "100.0",
  "amount_b": "200.0",
  "user_address": "user-address"
}
```

### POST /contracts/lending

Interact with the Lending Protocol.

**Supply Collateral Request:**
```json
{
  "action": "supply",
  "asset": "token-address",
  "amount": "1000.0",
  "user_address": "user-address"
}
```

**Borrow Asset Request:**
```json
{
  "action": "borrow",
  "asset": "token-address",
  "amount": "500.0",
  "collateral": "collateral-token-address",
  "user_address": "user-address"
}
```

### POST /contracts/derivatives

Interact with the Derivatives Exchange.

**Create Option Request:**
```json
{
  "action": "create_option",
  "underlying_asset": "token-address",
  "strike_price": "100.0",
  "expiry_date": "2024-12-31T23:59:59Z",
  "option_type": "call",
  "premium": "5.0"
}
```

## Oracle Endpoints

### GET /oracle/price/{symbol}

Get price data for a specific asset.

**Response:**
```json
{
  "success": true,
  "data": {
    "symbol": "BTC",
    "price": "45000.00",
    "timestamp": "2024-01-01T00:00:00Z",
    "source": "aggregated",
    "confidence": 0.95,
    "volume_24h": "1000000000"
  }
}
```

### POST /oracle

Register oracle or submit oracle data.

**Register Oracle Request:**
```json
{
  "action": "register",
  "oracle_address": "oracle-address",
  "supported_feeds": ["BTC", "ETH", "USDT"],
  "stake_amount": "1000.0"
}
```

**Submit Data Request:**
```json
{
  "action": "submit_data",
  "oracle_address": "oracle-address",
  "symbol": "BTC",
  "price": "45000.00",
  "timestamp": "2024-01-01T00:00:00Z",
  "signature": "data-signature"
}
```

### GET /oracle/market

Get comprehensive market data.

**Response:**
```json
{
  "success": true,
  "data": {
    "markets": {
      "BTC": {
        "price": "45000.00",
        "change_24h": "+2.5%",
        "volume_24h": "1000000000",
        "market_cap": "900000000000"
      },
      "ETH": {
        "price": "3000.00",
        "change_24h": "+1.8%",
        "volume_24h": "500000000",
        "market_cap": "360000000000"
      }
    },
    "total_market_cap": "2500000000000",
    "last_updated": "2024-01-01T00:00:00Z"
  }
}
```

## Rate Limiting

The API implements rate limiting to ensure fair usage:

- **General endpoints**: 100 requests per minute
- **Authentication endpoints**: 10 requests per minute
- **Transaction endpoints**: 50 requests per minute

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
```

## WebSocket API

For real-time updates, connect to the WebSocket endpoint:

```
ws://localhost:5000/ws
```

### Subscription Messages

**Subscribe to new blocks:**
```json
{
  "type": "subscribe",
  "channel": "blocks"
}
```

**Subscribe to transactions:**
```json
{
  "type": "subscribe",
  "channel": "transactions",
  "filter": {
    "address": "specific-address"
  }
}
```

**Subscribe to price updates:**
```json
{
  "type": "subscribe",
  "channel": "prices",
  "symbols": ["BTC", "ETH"]
}
```

## SDK Examples

### Python SDK

```python
import requests

class SmartContractAPI:
    def __init__(self, base_url="http://localhost:5000/api"):
        self.base_url = base_url
        self.token = None
    
    def login(self, username, password):
        response = requests.post(f"{self.base_url}/auth/login", json={
            "username": username,
            "password": password
        })
        if response.status_code == 200:
            self.token = response.json()["data"]["token"]
            return True
        return False
    
    def get_headers(self):
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}
    
    def get_blockchain_info(self):
        response = requests.get(f"{self.base_url}/blockchain/info")
        return response.json()
    
    def send_transaction(self, from_addr, to_addr, amount):
        response = requests.post(f"{self.base_url}/blockchain/transaction", 
                               json={
                                   "from_address": from_addr,
                                   "to_address": to_addr,
                                   "amount": str(amount)
                               },
                               headers=self.get_headers())
        return response.json()

# Usage
api = SmartContractAPI()
api.login("username", "password")
info = api.get_blockchain_info()
print(f"Blockchain height: {info['data']['height']}")
```

### JavaScript SDK

```javascript
class SmartContractAPI {
    constructor(baseUrl = 'http://localhost:5000/api') {
        this.baseUrl = baseUrl;
        this.token = null;
    }
    
    async login(username, password) {
        const response = await fetch(`${this.baseUrl}/auth/login`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, password})
        });
        
        if (response.ok) {
            const data = await response.json();
            this.token = data.data.token;
            return true;
        }
        return false;
    }
    
    getHeaders() {
        return this.token ? {'Authorization': `Bearer ${this.token}`} : {};
    }
    
    async getBlockchainInfo() {
        const response = await fetch(`${this.baseUrl}/blockchain/info`);
        return await response.json();
    }
    
    async sendTransaction(fromAddr, toAddr, amount) {
        const response = await fetch(`${this.baseUrl}/blockchain/transaction`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                ...this.getHeaders()
            },
            body: JSON.stringify({
                from_address: fromAddr,
                to_address: toAddr,
                amount: amount.toString()
            })
        });
        return await response.json();
    }
}

// Usage
const api = new SmartContractAPI();
await api.login('username', 'password');
const info = await api.getBlockchainInfo();
console.log(`Blockchain height: ${info.data.height}`);
```

## Testing

Use the provided test endpoints to verify API functionality:

```bash
# Health check
curl http://localhost:5000/api/health

# Get blockchain info
curl http://localhost:5000/api/blockchain/info

# Login and get token
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test"}'
```

## Support

For API support and questions:
- Documentation: [GitHub Repository](https://github.com/your-repo/smart-contract-platform)
- Issues: [GitHub Issues](https://github.com/your-repo/smart-contract-platform/issues)
- Email: support@smartcontractplatform.com