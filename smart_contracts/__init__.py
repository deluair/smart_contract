"""Smart Contracts Module

This module provides smart contract functionality including:
- Virtual Machine for contract execution
- Contract engine and deployment
- Standard contract templates (ERC20, DEX, Lending, etc.)
- Contract compilation and validation
- Gas metering and execution limits

Components:
- VM: Virtual machine for contract execution
- Engine: Contract deployment and management
- ERC20: Standard token contract
- DEX: Decentralized exchange contract
- Lending: Lending protocol contract
- Derivatives: Options and futures contracts
"""

# Import core smart contract components
from .engine.vm import SmartContractVM
from .engine.engine import SmartContractEngine
from .financial.token import ERC20Token
from .financial.dex import DecentralizedExchange
from .financial.lending import LendingProtocol
from .financial.derivatives import DerivativesExchange

__all__ = [
    'SmartContractVM',
    'SmartContractEngine',
    'ERC20Token',
    'DecentralizedExchange', 
    'LendingProtocol',
    'DerivativesExchange',
    'create_contract_engine',
    'deploy_contract',
    'validate_contract_code'
]

__version__ = '1.0.0'
__author__ = 'Smart Contract Platform Team'

# Configuration constants
DEFAULT_GAS_LIMIT = 1000000
MAX_CONTRACT_SIZE = 24576  # bytes
MAX_STACK_SIZE = 1024
MAX_MEMORY_SIZE = 1024 * 1024  # 1MB

def create_contract_engine(blockchain=None, gas_limit=DEFAULT_GAS_LIMIT):
    """Create a smart contract engine
    
    Args:
        blockchain: Blockchain instance
        gas_limit: Default gas limit for contracts
    
    Returns:
        SmartContractEngine: Configured contract engine
    """
    engine = SmartContractEngine()
    
    return engine

def deploy_contract(engine, contract_code, constructor_args=None, sender=None):
    """Deploy a smart contract
    
    Args:
        engine (SmartContractEngine): Contract engine
        contract_code (str): Contract bytecode or source
        constructor_args (list): Constructor arguments
        sender (str): Deployer address
    
    Returns:
        dict: Deployment result with contract address
    """
    try:
        result = engine.deploy_contract(
            code=contract_code,
            constructor_args=constructor_args or [],
            sender=sender
        )
        return {
            'success': True,
            'contract_address': result.get('contract_address'),
            'transaction_hash': result.get('transaction_hash'),
            'gas_used': result.get('gas_used', 0)
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }

def validate_contract_code(code):
    """Validate contract code
    
    Args:
        code (str): Contract code to validate
    
    Returns:
        tuple: (is_valid, error_message)
    """
    try:
        if not code or not isinstance(code, str):
            return False, "Contract code must be a non-empty string"
        
        if len(code.encode('utf-8')) > MAX_CONTRACT_SIZE:
            return False, f"Contract size exceeds maximum of {MAX_CONTRACT_SIZE} bytes"
        
        # Basic syntax validation (simplified)
        forbidden_ops = ['SELFDESTRUCT', 'DELEGATECALL']
        for op in forbidden_ops:
            if op in code.upper():
                return False, f"Forbidden operation: {op}"
        
        return True, None
        
    except Exception as e:
        return False, f"Validation error: {str(e)}"

# Contract templates
CONTRACT_TEMPLATES = {
    'erc20': {
        'name': 'ERC20 Token',
        'description': 'Standard fungible token contract',
        'constructor_args': ['name', 'symbol', 'total_supply', 'decimals']
    },
    'dex': {
        'name': 'Decentralized Exchange',
        'description': 'AMM-based decentralized exchange',
        'constructor_args': ['fee_rate']
    },
    'lending': {
        'name': 'Lending Protocol',
        'description': 'Collateralized lending and borrowing',
        'constructor_args': ['collateral_ratio', 'liquidation_threshold']
    },
    'derivatives': {
        'name': 'Derivatives Contract',
        'description': 'Options and futures trading',
        'constructor_args': ['underlying_asset', 'oracle_address']
    }
}

def get_contract_template(template_name):
    """Get contract template information
    
    Args:
        template_name (str): Name of the template
    
    Returns:
        dict: Template information or None
    """
    return CONTRACT_TEMPLATES.get(template_name.lower())

def list_contract_templates():
    """List available contract templates
    
    Returns:
        dict: Available templates
    """
    return CONTRACT_TEMPLATES.copy()

# Gas price configuration
GAS_PRICES = {
    'STOP': 0,
    'ADD': 3,
    'MUL': 5,
    'SUB': 3,
    'DIV': 5,
    'MOD': 5,
    'EXP': 10,
    'LT': 3,
    'GT': 3,
    'EQ': 3,
    'ISZERO': 3,
    'AND': 3,
    'OR': 3,
    'XOR': 3,
    'NOT': 3,
    'BYTE': 3,
    'KECCAK256': 30,
    'ADDRESS': 2,
    'BALANCE': 400,
    'CALLER': 2,
    'CALLVALUE': 2,
    'CALLDATALOAD': 3,
    'CALLDATASIZE': 2,
    'CALLDATACOPY': 3,
    'CODESIZE': 2,
    'CODECOPY': 3,
    'GASPRICE': 2,
    'BLOCKHASH': 20,
    'COINBASE': 2,
    'TIMESTAMP': 2,
    'NUMBER': 2,
    'DIFFICULTY': 2,
    'GASLIMIT': 2,
    'POP': 2,
    'MLOAD': 3,
    'MSTORE': 3,
    'MSTORE8': 3,
    'SLOAD': 200,
    'SSTORE': 5000,
    'JUMP': 8,
    'JUMPI': 10,
    'PC': 2,
    'MSIZE': 2,
    'GAS': 2,
    'JUMPDEST': 1,
    'PUSH1': 3,
    'PUSH32': 3,
    'DUP1': 3,
    'DUP16': 3,
    'SWAP1': 3,
    'SWAP16': 3,
    'LOG0': 375,
    'LOG4': 375,
    'CREATE': 32000,
    'CALL': 700,
    'CALLCODE': 700,
    'RETURN': 0,
    'DELEGATECALL': 700,
    'STATICCALL': 700,
    'REVERT': 0,
    'SELFDESTRUCT': 5000
}

# Global contract engine instance (singleton)
_contract_engine_instance = None

def get_contract_engine_instance():
    """Get the global contract engine instance
    
    Returns:
        SmartContractEngine: Global contract engine instance
    """
    global _contract_engine_instance
    if _contract_engine_instance is None:
        _contract_engine_instance = create_contract_engine()
    return _contract_engine_instance

def reset_contract_engine_instance():
    """Reset the global contract engine instance"""
    global _contract_engine_instance
    _contract_engine_instance = None

# Export configuration
CONFIG = {
    'DEFAULT_GAS_LIMIT': DEFAULT_GAS_LIMIT,
    'MAX_CONTRACT_SIZE': MAX_CONTRACT_SIZE,
    'MAX_STACK_SIZE': MAX_STACK_SIZE,
    'MAX_MEMORY_SIZE': MAX_MEMORY_SIZE,
    'GAS_PRICES': GAS_PRICES,
    'CONTRACT_TEMPLATES': CONTRACT_TEMPLATES
}

print(f"Smart Contracts module loaded - Version {__version__}")
print(f"Available templates: {list(CONTRACT_TEMPLATES.keys())}")
print(f"Default gas limit: {DEFAULT_GAS_LIMIT:,}")