"""Financial Smart Contracts Module

This module contains smart contracts specifically designed for financial markets,
including:

- Token contracts (ERC-20 compatible with financial features)
- Decentralized Exchange (DEX) with AMM capabilities
- Lending Protocol for collateralized loans
- Derivatives Exchange for options, futures, and swaps

All contracts are built on top of the smart contract engine and provide
comprehensive financial market functionality.
"""

from .token import ERC20Token
from .dex import DecentralizedExchange, LiquidityPool
from .lending import LendingProtocol, Loan, CollateralPosition, InterestRateModel
from .derivatives import (
    DerivativesExchange,
    DerivativeContract,
    OptionTerms,
    FutureTerms,
    SwapTerms,
    MarginAccount,
    DerivativeType,
    OptionStyle,
    DerivativeStatus,
    SwapType
)

__all__ = [
    # Token contracts
    'ERC20Token',
    
    # DEX contracts
    'DecentralizedExchange',
    'LiquidityPool',
    
    # Lending contracts
    'LendingProtocol',
    'Loan',
    'CollateralPosition',
    'InterestRateModel',
    
    # Derivatives contracts
    'DerivativesExchange',
    'DerivativeContract',
    'OptionTerms',
    'FutureTerms',
    'SwapTerms',
    'MarginAccount',
    'DerivativeType',
    'OptionStyle',
    'DerivativeStatus',
    'SwapType'
]

__version__ = '1.0.0'
__author__ = 'Blockchain Financial System'

# Financial market constants
BASIS_POINTS_SCALE = 10000  # 1 basis point = 0.01%
PRICE_SCALE = 10**8  # Price scaling factor
TIME_SCALE = 86400  # Seconds in a day

# Default financial parameters
DEFAULT_TRADING_FEE = 30  # 0.3% in basis points
DEFAULT_SLIPPAGE_TOLERANCE = 50  # 0.5% in basis points
DEFAULT_LIQUIDATION_THRESHOLD = 8000  # 80% in basis points
DEFAULT_MARGIN_REQUIREMENT = 1000  # 10% in basis points

# Risk management constants
MAX_LEVERAGE = 10  # Maximum leverage allowed
MIN_COLLATERAL_RATIO = 15000  # 150% minimum collateral ratio
LIQUIDATION_PENALTY = 500  # 5% liquidation penalty

def get_financial_contracts():
    """Get a dictionary of all available financial contract classes"""
    return {
        'token': ERC20Token,
        'dex': DecentralizedExchange,
        'lending': LendingProtocol,
        'derivatives': DerivativesExchange
    }

def create_financial_ecosystem(owner: str):
    """Create a complete financial ecosystem with all contracts"""
    contracts = {
        'token': ERC20Token(
            name="Financial System Token",
            symbol="FST",
            decimals=18,
            initial_supply=1000000 * 10**18,
            owner=owner
        ),
        'dex': DecentralizedExchange(owner=owner),
        'lending': LendingProtocol(owner=owner),
        'derivatives': DerivativesExchange(owner=owner)
    }
    
    return contracts