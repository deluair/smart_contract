"""Wallet and Account Management Module

This module provides comprehensive wallet and account management functionality
for the blockchain system, including:

- HD (Hierarchical Deterministic) wallets with BIP44 support
- Multi-signature wallet support
- Account creation and management
- Transaction signing and management
- User authentication and authorization
- Role-based access control
- Session management
- Two-factor authentication
- Security features and audit logging

Classes:
    Wallet: Main wallet class with HD and multisig support
    HDWallet: Hierarchical Deterministic wallet implementation
    Account: Individual account within a wallet
    AccountManager: User and wallet management system
    UserProfile: User profile and permissions
    UserSession: Session management
    
Enums:
    WalletType: Types of wallets (HD, Simple, Multisig, Hardware)
    AccountType: Types of accounts (Standard, Savings, Trading, Staking, Multisig)
    UserRole: User roles (Admin, User, Trader, Validator, ReadOnly)
    PermissionType: Available permissions
    TransactionStatus: Transaction status tracking
    SessionStatus: Session status tracking

Example:
    >>> from wallet import AccountManager, WalletType
    >>> 
    >>> # Create account manager
    >>> manager = AccountManager("secret_key")
    >>> 
    >>> # Create user
    >>> user_id = manager.create_user(
    ...     username="alice",
    ...     email="alice@example.com",
    ...     password="secure_password",
    ...     full_name="Alice Smith"
    ... )
    >>> 
    >>> # Authenticate user
    >>> session_id = manager.authenticate_user("alice", "secure_password")
    >>> 
    >>> # Create wallet for user
    >>> wallet_id = manager.create_wallet_for_user(user_id, WalletType.HD_WALLET)
    >>> 
    >>> # Create account in wallet
    >>> account_id = manager.create_account_for_user(
    ...     user_id, wallet_id, "My Account"
    ... )
"""

from .wallet import (
    Wallet,
    HDWallet,
    HDKey,
    Account,
    WalletTransaction,
    MultiSigConfig,
    WalletType,
    AccountType,
    TransactionStatus
)

from .account_manager import (
    AccountManager,
    UserProfile,
    UserSession,
    Permission,
    LoginAttempt,
    UserRole,
    PermissionType,
    SessionStatus
)

__all__ = [
    # Wallet classes
    'Wallet',
    'HDWallet',
    'HDKey',
    'Account',
    'WalletTransaction',
    'MultiSigConfig',
    
    # Account management classes
    'AccountManager',
    'UserProfile',
    'UserSession',
    'Permission',
    'LoginAttempt',
    
    # Enums
    'WalletType',
    'AccountType',
    'TransactionStatus',
    'UserRole',
    'PermissionType',
    'SessionStatus',
    
    # Utility functions
    'create_wallet_system',
    'get_wallet_info',
    'validate_mnemonic'
]

__version__ = "1.0.0"
__author__ = "Blockchain Development Team"

# Wallet system constants
DEFAULT_DERIVATION_PATH = "m/44'/0'/0'/0/0"
MIN_PASSWORD_LENGTH = 8
SESSION_TIMEOUT = 3600  # 1 hour
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = 1800  # 30 minutes
BACKUP_CODE_COUNT = 10

# Supported wallet types
SUPPORTED_WALLET_TYPES = [
    WalletType.HD_WALLET,
    WalletType.SIMPLE_WALLET,
    WalletType.MULTISIG_WALLET
]

# Default permissions by role
DEFAULT_ROLE_PERMISSIONS = {
    UserRole.ADMIN: [
        PermissionType.CREATE_WALLET,
        PermissionType.DELETE_WALLET,
        PermissionType.CREATE_ACCOUNT,
        PermissionType.DELETE_ACCOUNT,
        PermissionType.SEND_TRANSACTION,
        PermissionType.VIEW_BALANCE,
        PermissionType.VIEW_TRANSACTIONS,
        PermissionType.MANAGE_MULTISIG,
        PermissionType.EXPORT_KEYS,
        PermissionType.IMPORT_KEYS,
        PermissionType.STAKE_TOKENS,
        PermissionType.TRADE_TOKENS,
        PermissionType.MANAGE_CONTRACTS,
        PermissionType.SYSTEM_ADMIN
    ],
    UserRole.TRADER: [
        PermissionType.CREATE_WALLET,
        PermissionType.CREATE_ACCOUNT,
        PermissionType.SEND_TRANSACTION,
        PermissionType.VIEW_BALANCE,
        PermissionType.VIEW_TRANSACTIONS,
        PermissionType.TRADE_TOKENS,
        PermissionType.STAKE_TOKENS
    ],
    UserRole.USER: [
        PermissionType.CREATE_WALLET,
        PermissionType.CREATE_ACCOUNT,
        PermissionType.SEND_TRANSACTION,
        PermissionType.VIEW_BALANCE,
        PermissionType.VIEW_TRANSACTIONS
    ]
}

def create_wallet_system(secret_key: str, session_timeout: int = SESSION_TIMEOUT) -> AccountManager:
    """Create a complete wallet management system
    
    Args:
        secret_key: Secret key for session management
        session_timeout: Session timeout in seconds
        
    Returns:
        AccountManager: Configured account manager instance
        
    Example:
        >>> wallet_system = create_wallet_system("my_secret_key")
        >>> user_id = wallet_system.create_user("alice", "alice@example.com", "password", "Alice")
    """
    return AccountManager(secret_key, session_timeout)

def get_wallet_info(wallet: Wallet) -> dict:
    """Get comprehensive wallet information
    
    Args:
        wallet: Wallet instance
        
    Returns:
        dict: Wallet information including accounts, balances, and transactions
        
    Example:
        >>> info = get_wallet_info(my_wallet)
        >>> print(f"Wallet has {info['total_accounts']} accounts")
    """
    return wallet.get_wallet_info()

def validate_mnemonic(mnemonic: str) -> bool:
    """Validate BIP39 mnemonic phrase
    
    Args:
        mnemonic: Mnemonic phrase to validate
        
    Returns:
        bool: True if mnemonic is valid, False otherwise
        
    Example:
        >>> is_valid = validate_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        >>> print(f"Mnemonic is valid: {is_valid}")
    """
    try:
        from mnemonic import Mnemonic
        m = Mnemonic("english")
        return m.check(mnemonic)
    except Exception:
        return False

def create_hd_wallet(mnemonic: str = None, passphrase: str = "") -> HDWallet:
    """Create a new HD wallet
    
    Args:
        mnemonic: Optional mnemonic phrase (generates new if not provided)
        passphrase: Optional passphrase for additional security
        
    Returns:
        HDWallet: New HD wallet instance
        
    Example:
        >>> hd_wallet = create_hd_wallet()
        >>> print(f"Mnemonic: {hd_wallet.mnemonic}")
    """
    return HDWallet(mnemonic, passphrase)

def create_multisig_wallet(wallet_id: str, required_signatures: int, 
                          signer_public_keys: list) -> Wallet:
    """Create a new multisig wallet
    
    Args:
        wallet_id: Unique wallet identifier
        required_signatures: Number of required signatures
        signer_public_keys: List of signer public keys
        
    Returns:
        Wallet: New multisig wallet instance
        
    Example:
        >>> multisig_wallet = create_multisig_wallet(
        ...     "multisig_001", 2, ["pubkey1", "pubkey2", "pubkey3"]
        ... )
    """
    wallet = Wallet(wallet_id, WalletType.MULTISIG_WALLET)
    wallet.create_multisig_account(
        "Multisig Account", 
        required_signatures, 
        signer_public_keys
    )
    return wallet

def generate_secure_password(length: int = 16) -> str:
    """Generate a secure random password
    
    Args:
        length: Password length (minimum 8)
        
    Returns:
        str: Secure random password
        
    Example:
        >>> password = generate_secure_password(20)
        >>> print(f"Generated password: {password}")
    """
    import secrets
    import string
    
    if length < MIN_PASSWORD_LENGTH:
        length = MIN_PASSWORD_LENGTH
        
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def estimate_transaction_fee(transaction_size: int, fee_rate: int = 1000) -> int:
    """Estimate transaction fee based on size and fee rate
    
    Args:
        transaction_size: Transaction size in bytes
        fee_rate: Fee rate in satoshis per byte
        
    Returns:
        int: Estimated fee in satoshis
        
    Example:
        >>> fee = estimate_transaction_fee(250, 1000)
        >>> print(f"Estimated fee: {fee} satoshis")
    """
    return transaction_size * fee_rate

def format_balance(balance: int, decimals: int = 8, symbol: str = "BTC") -> str:
    """Format balance for display
    
    Args:
        balance: Balance in smallest unit (e.g., satoshis)
        decimals: Number of decimal places
        symbol: Currency symbol
        
    Returns:
        str: Formatted balance string
        
    Example:
        >>> formatted = format_balance(100000000, 8, "BTC")
        >>> print(formatted)  # "1.00000000 BTC"
    """
    decimal_balance = balance / (10 ** decimals)
    return f"{decimal_balance:.{decimals}f} {symbol}"

# Security utilities
def hash_password(password: str) -> str:
    """Hash password using bcrypt
    
    Args:
        password: Plain text password
        
    Returns:
        str: Hashed password
    """
    import bcrypt
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash
    
    Args:
        password: Plain text password
        hashed: Hashed password
        
    Returns:
        bool: True if password matches hash
    """
    import bcrypt
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# Export utility functions
__all__.extend([
    'create_hd_wallet',
    'create_multisig_wallet',
    'generate_secure_password',
    'estimate_transaction_fee',
    'format_balance',
    'hash_password',
    'verify_password'
])