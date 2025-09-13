"""API Module for Smart Contract Platform

This module provides REST API endpoints for interacting with the blockchain,
smart contracts, wallet management, and oracle systems.

Features:
- RESTful API endpoints
- JWT authentication
- Request validation
- Error handling
- Rate limiting
- CORS support
- API documentation

Components:
- REST API server
- Authentication middleware
- Request/response handlers
- API documentation
"""

from .rest_api import (
    BlockchainAPI,
    AuthResource,
    TransactionResource,
    WalletResource,
    TokenResource,
    DEXResource,
    LendingResource,
    DerivativesResource,
    OracleResource,
    MarketDataResource,
    create_app
)

__all__ = [
    'BlockchainAPI',
    'AuthResource', 
    'TransactionResource',
    'WalletResource',
    'TokenResource',
    'DEXResource',
    'LendingResource',
    'DerivativesResource',
    'OracleResource',
    'MarketDataResource',
    'create_app',
    'start_api_server',
    'validate_request',
    'handle_api_error'
]

__version__ = '1.0.0'
__author__ = 'Smart Contract Platform Team'

# API Configuration
API_VERSION = 'v1'
API_PREFIX = f'/api/{API_VERSION}'
DEFAULT_PORT = 5000
DEFAULT_HOST = '0.0.0.0'

# Rate limiting configuration
RATE_LIMIT_REQUESTS = 100
RATE_LIMIT_WINDOW = 60  # seconds

# CORS configuration
CORS_ORIGINS = ['http://localhost:3000', 'http://localhost:8080']

def start_api_server(host=DEFAULT_HOST, port=DEFAULT_PORT, debug=False):
    """Start the API server
    
    Args:
        host (str): Host to bind to
        port (int): Port to listen on
        debug (bool): Enable debug mode
    
    Returns:
        Flask app instance
    """
    app = create_app()
    
    print(f"Starting API server on {host}:{port}")
    print(f"API endpoints available at: http://{host}:{port}{API_PREFIX}")
    
    app.run(host=host, port=port, debug=debug)
    return app

def validate_request(request_data, required_fields):
    """Validate API request data
    
    Args:
        request_data (dict): Request data to validate
        required_fields (list): List of required field names
    
    Returns:
        tuple: (is_valid, error_message)
    """
    if not isinstance(request_data, dict):
        return False, "Request data must be a JSON object"
    
    missing_fields = []
    for field in required_fields:
        if field not in request_data or request_data[field] is None:
            missing_fields.append(field)
    
    if missing_fields:
        return False, f"Missing required fields: {', '.join(missing_fields)}"
    
    return True, None

def handle_api_error(error, status_code=500):
    """Handle API errors consistently
    
    Args:
        error (Exception or str): Error to handle
        status_code (int): HTTP status code
    
    Returns:
        dict: Error response
    """
    error_message = str(error) if isinstance(error, Exception) else error
    
    return {
        'success': False,
        'error': error_message,
        'status_code': status_code
    }

# Global API instance (singleton)
_api_instance = None

def get_api_instance():
    """Get the global API instance
    
    Returns:
        BlockchainAPI: Global API instance
    """
    global _api_instance
    if _api_instance is None:
        _api_instance = BlockchainAPI()
    return _api_instance

def health_check():
    """Perform API health check
    
    Returns:
        dict: Health status
    """
    try:
        api = get_api_instance()
        
        # Check blockchain connection
        blockchain_status = api.blockchain is not None
        
        # Check oracle system
        oracle_status = api.oracle_manager is not None
        
        # Check wallet system
        wallet_status = api.account_manager is not None
        
        return {
            'status': 'healthy',
            'components': {
                'blockchain': blockchain_status,
                'oracles': oracle_status,
                'wallet': wallet_status
            },
            'version': __version__,
            'timestamp': __import__('time').time()
        }
    except Exception as e:
        return {
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': __import__('time').time()
        }

# API endpoint mappings
API_ENDPOINTS = {
    'auth': {
        'login': 'POST /auth/login',
        'register': 'POST /auth/register',
        'logout': 'POST /auth/logout',
        'refresh': 'POST /auth/refresh'
    },
    'blockchain': {
        'info': 'GET /blockchain/info',
        'transaction': 'POST /blockchain/transaction',
        'block': 'GET /blockchain/block/<block_id>',
        'balance': 'GET /blockchain/balance/<address>'
    },
    'wallet': {
        'create': 'POST /wallet',
        'list': 'GET /wallet',
        'balance': 'GET /wallet/<address>/balance',
        'transactions': 'GET /wallet/<address>/transactions'
    },
    'smart_contracts': {
        'deploy': 'POST /contracts/deploy',
        'call': 'POST /contracts/call',
        'erc20': 'POST /contracts/erc20',
        'dex': 'POST /contracts/dex',
        'lending': 'POST /contracts/lending'
    },
    'oracle': {
        'price': 'GET /oracle/price/<symbol>',
        'feeds': 'GET /oracle/feeds',
        'nodes': 'GET /oracle/nodes',
        'request': 'POST /oracle/request'
    },
    'market': {
        'data': 'GET /market/data',
        'pools': 'GET /market/pools',
        'stats': 'GET /market/stats'
    }
}

# Export configuration
CONFIG = {
    'API_VERSION': API_VERSION,
    'API_PREFIX': API_PREFIX,
    'DEFAULT_PORT': DEFAULT_PORT,
    'DEFAULT_HOST': DEFAULT_HOST,
    'RATE_LIMIT_REQUESTS': RATE_LIMIT_REQUESTS,
    'RATE_LIMIT_WINDOW': RATE_LIMIT_WINDOW,
    'CORS_ORIGINS': CORS_ORIGINS
}

print(f"API module loaded - Version {__version__}")
print(f"Available endpoints: {len(sum([list(endpoints.keys()) for endpoints in API_ENDPOINTS.values()], []))}")