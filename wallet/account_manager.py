from typing import Dict, List, Optional, Set, Tuple, Union
import os
import json
import time
import hashlib
import secrets
import bcrypt
from dataclasses import dataclass, field
from enum import Enum
from decimal import Decimal
import jwt
from datetime import datetime, timedelta

from .wallet import Wallet, WalletType, Account, AccountType
from security.cryptography import CryptoUtils

class UserRole(Enum):
    ADMIN = "ADMIN"
    USER = "USER"
    TRADER = "TRADER"
    VALIDATOR = "VALIDATOR"
    READONLY = "READONLY"

class PermissionType(Enum):
    CREATE_WALLET = "CREATE_WALLET"
    DELETE_WALLET = "DELETE_WALLET"
    CREATE_ACCOUNT = "CREATE_ACCOUNT"
    DELETE_ACCOUNT = "DELETE_ACCOUNT"
    SEND_TRANSACTION = "SEND_TRANSACTION"
    VIEW_BALANCE = "VIEW_BALANCE"
    VIEW_TRANSACTIONS = "VIEW_TRANSACTIONS"
    MANAGE_MULTISIG = "MANAGE_MULTISIG"
    EXPORT_KEYS = "EXPORT_KEYS"
    IMPORT_KEYS = "IMPORT_KEYS"
    STAKE_TOKENS = "STAKE_TOKENS"
    TRADE_TOKENS = "TRADE_TOKENS"
    MANAGE_CONTRACTS = "MANAGE_CONTRACTS"
    SYSTEM_ADMIN = "SYSTEM_ADMIN"

class SessionStatus(Enum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    LOCKED = "LOCKED"

@dataclass
class Permission:
    """User permission"""
    permission_type: PermissionType
    resource_id: Optional[str] = None  # Specific resource (wallet_id, account_id, etc.)
    granted_at: int = field(default_factory=lambda: int(time.time()))
    granted_by: Optional[str] = None
    expires_at: Optional[int] = None
    
    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return int(time.time()) > self.expires_at

@dataclass
class UserProfile:
    """User profile information"""
    user_id: str
    username: str
    email: str
    full_name: str
    role: UserRole
    permissions: List[Permission] = field(default_factory=list)
    created_at: int = field(default_factory=lambda: int(time.time()))
    last_login: Optional[int] = None
    is_active: bool = True
    is_verified: bool = False
    failed_login_attempts: int = 0
    locked_until: Optional[int] = None
    
    # Security settings
    two_factor_enabled: bool = False
    two_factor_secret: Optional[str] = None
    backup_codes: List[str] = field(default_factory=list)
    
    # Preferences
    default_currency: str = "USD"
    timezone: str = "UTC"
    notification_preferences: Dict[str, bool] = field(default_factory=dict)
    
    @property
    def is_locked(self) -> bool:
        if self.locked_until is None:
            return False
        return int(time.time()) < self.locked_until
        
    def has_permission(self, permission_type: PermissionType, resource_id: Optional[str] = None) -> bool:
        """Check if user has specific permission"""
        if not self.is_active or self.is_locked:
            return False
            
        for perm in self.permissions:
            if perm.permission_type == permission_type and not perm.is_expired:
                if resource_id is None or perm.resource_id is None or perm.resource_id == resource_id:
                    return True
        return False

@dataclass
class UserSession:
    """User session information"""
    session_id: str
    user_id: str
    created_at: int
    last_activity: int
    expires_at: int
    ip_address: str
    user_agent: str
    status: SessionStatus = SessionStatus.ACTIVE
    
    @property
    def is_expired(self) -> bool:
        return int(time.time()) > self.expires_at
        
    @property
    def is_valid(self) -> bool:
        return self.status == SessionStatus.ACTIVE and not self.is_expired

@dataclass
class LoginAttempt:
    """Login attempt record"""
    user_id: str
    ip_address: str
    timestamp: int
    success: bool
    failure_reason: Optional[str] = None

class AccountManager:
    """Comprehensive Account Management System"""
    
    def __init__(self, secret_key: str, session_timeout: int = 3600):
        self.secret_key = secret_key
        self.session_timeout = session_timeout
        
        # User management
        self.users: Dict[str, UserProfile] = {}
        self.user_credentials: Dict[str, str] = {}  # user_id -> password_hash
        self.username_to_user_id: Dict[str, str] = {}
        self.email_to_user_id: Dict[str, str] = {}
        
        # Session management
        self.active_sessions: Dict[str, UserSession] = {}
        self.user_sessions: Dict[str, Set[str]] = {}  # user_id -> session_ids
        
        # Wallet management
        self.user_wallets: Dict[str, List[str]] = {}  # user_id -> wallet_ids
        self.wallets: Dict[str, Wallet] = {}
        
        # Security
        self.crypto_utils = CryptoUtils()
        self.login_attempts: List[LoginAttempt] = []
        
        # Role-based permissions
        self.role_permissions = self._initialize_role_permissions()
        
        # Create default admin user
        self._create_default_admin()
        
    def _initialize_role_permissions(self) -> Dict[UserRole, List[PermissionType]]:
        """Initialize default role permissions"""
        return {
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
            ],
            UserRole.VALIDATOR: [
                PermissionType.VIEW_BALANCE,
                PermissionType.VIEW_TRANSACTIONS,
                PermissionType.STAKE_TOKENS
            ],
            UserRole.READONLY: [
                PermissionType.VIEW_BALANCE,
                PermissionType.VIEW_TRANSACTIONS
            ]
        }
        
    def _create_default_admin(self):
        """Create default admin user"""
        admin_id = "admin_" + secrets.token_hex(8)
        admin_password = "admin123"  # Should be changed in production
        
        self.create_user(
            username="admin",
            email="admin@blockchain.local",
            password=admin_password,
            full_name="System Administrator",
            role=UserRole.ADMIN
        )
        
    def create_user(self, username: str, email: str, password: str, 
                   full_name: str, role: UserRole = UserRole.USER) -> str:
        """Create a new user"""
        # Validate input
        if username in self.username_to_user_id:
            raise ValueError("Username already exists")
        if email in self.email_to_user_id:
            raise ValueError("Email already exists")
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
            
        # Generate user ID
        user_id = f"user_{secrets.token_hex(16)}"
        
        # Hash password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Create user profile
        user_profile = UserProfile(
            user_id=user_id,
            username=username,
            email=email,
            full_name=full_name,
            role=role
        )
        
        # Add role-based permissions
        for perm_type in self.role_permissions.get(role, []):
            permission = Permission(permission_type=perm_type)
            user_profile.permissions.append(permission)
            
        # Store user data
        self.users[user_id] = user_profile
        self.user_credentials[user_id] = password_hash
        self.username_to_user_id[username] = user_id
        self.email_to_user_id[email] = user_id
        self.user_wallets[user_id] = []
        self.user_sessions[user_id] = set()
        
        return user_id
    
    def register_user(self, username: str, email: str, password: str) -> str:
        """Register a new user with default settings"""
        # Use username as full_name if not provided, with default USER role
        full_name = username.replace('_', ' ').title()
        return self.create_user(username, email, password, full_name, UserRole.USER)
        
    def authenticate_user(self, username: str, password: str, 
                         ip_address: str = "unknown", user_agent: str = "unknown") -> Optional[str]:
        """Authenticate user and create session"""
        # Find user
        user_id = self.username_to_user_id.get(username)
        if not user_id or user_id not in self.users:
            self._record_login_attempt(username, ip_address, False, "User not found")
            return None
            
        user = self.users[user_id]
        
        # Check if user is locked
        if user.is_locked:
            self._record_login_attempt(user_id, ip_address, False, "Account locked")
            return None
            
        # Check if user is active
        if not user.is_active:
            self._record_login_attempt(user_id, ip_address, False, "Account inactive")
            return None
            
        # Verify password
        stored_hash = self.user_credentials[user_id]
        if not bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
            user.failed_login_attempts += 1
            
            # Lock account after 5 failed attempts
            if user.failed_login_attempts >= 5:
                user.locked_until = int(time.time()) + 1800  # Lock for 30 minutes
                
            self._record_login_attempt(user_id, ip_address, False, "Invalid password")
            return None
            
        # Reset failed attempts on successful login
        user.failed_login_attempts = 0
        user.last_login = int(time.time())
        
        # Create session
        session_id = self._create_session(user_id, ip_address, user_agent)
        
        self._record_login_attempt(user_id, ip_address, True)
        
        return session_id
        
    def _create_session(self, user_id: str, ip_address: str, user_agent: str) -> str:
        """Create a new user session"""
        session_id = secrets.token_urlsafe(32)
        current_time = int(time.time())
        
        session = UserSession(
            session_id=session_id,
            user_id=user_id,
            created_at=current_time,
            last_activity=current_time,
            expires_at=current_time + self.session_timeout,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        self.active_sessions[session_id] = session
        self.user_sessions[user_id].add(session_id)
        
        return session_id
        
    def validate_session(self, session_id: str) -> Optional[UserProfile]:
        """Validate session and return user profile"""
        if session_id not in self.active_sessions:
            return None
            
        session = self.active_sessions[session_id]
        
        if not session.is_valid:
            self._cleanup_session(session_id)
            return None
            
        # Update last activity
        session.last_activity = int(time.time())
        session.expires_at = session.last_activity + self.session_timeout
        
        return self.users.get(session.user_id)
        
    def logout_user(self, session_id: str) -> bool:
        """Logout user by revoking session"""
        if session_id in self.active_sessions:
            session = self.active_sessions[session_id]
            session.status = SessionStatus.REVOKED
            self._cleanup_session(session_id)
            return True
        return False
        
    def logout_all_sessions(self, user_id: str) -> int:
        """Logout all sessions for a user"""
        if user_id not in self.user_sessions:
            return 0
            
        session_ids = list(self.user_sessions[user_id])
        count = 0
        
        for session_id in session_ids:
            if self.logout_user(session_id):
                count += 1
                
        return count
        
    def _cleanup_session(self, session_id: str):
        """Clean up expired or revoked session"""
        if session_id in self.active_sessions:
            session = self.active_sessions[session_id]
            user_id = session.user_id
            
            del self.active_sessions[session_id]
            
            if user_id in self.user_sessions:
                self.user_sessions[user_id].discard(session_id)
                
    def create_wallet_for_user(self, user_id: str, wallet_type: WalletType = WalletType.HD_WALLET) -> str:
        """Create a new wallet for user"""
        if user_id not in self.users:
            raise ValueError("User not found")
            
        user = self.users[user_id]
        if not user.has_permission(PermissionType.CREATE_WALLET):
            raise PermissionError("User does not have permission to create wallets")
            
        # Generate wallet ID
        wallet_id = f"wallet_{user_id}_{secrets.token_hex(8)}"
        
        # Create wallet
        wallet = Wallet(wallet_id, wallet_type)
        
        # Initialize HD wallet if needed
        if wallet_type == WalletType.HD_WALLET:
            mnemonic = wallet.initialize_hd_wallet()
            # In production, securely store or return mnemonic to user
            
        # Store wallet
        self.wallets[wallet_id] = wallet
        self.user_wallets[user_id].append(wallet_id)
        
        return wallet_id
        
    def get_user_wallets(self, user_id: str) -> List[str]:
        """Get all wallets for a user"""
        return self.user_wallets.get(user_id, [])
        
    def get_wallet(self, user_id: str, wallet_id: str) -> Optional[Wallet]:
        """Get wallet if user has access"""
        if wallet_id not in self.user_wallets.get(user_id, []):
            return None
        return self.wallets.get(wallet_id)
        
    def create_account_for_user(self, user_id: str, wallet_id: str, 
                               account_name: str, account_type: AccountType = AccountType.STANDARD) -> str:
        """Create account in user's wallet"""
        wallet = self.get_wallet(user_id, wallet_id)
        if not wallet:
            raise ValueError("Wallet not found or access denied")
            
        user = self.users[user_id]
        if not user.has_permission(PermissionType.CREATE_ACCOUNT):
            raise PermissionError("User does not have permission to create accounts")
            
        return wallet.create_account(account_name, account_type)
        
    def grant_permission(self, admin_user_id: str, target_user_id: str, 
                        permission_type: PermissionType, resource_id: Optional[str] = None,
                        expires_at: Optional[int] = None) -> bool:
        """Grant permission to user"""
        # Check admin permissions
        admin_user = self.users.get(admin_user_id)
        if not admin_user or not admin_user.has_permission(PermissionType.SYSTEM_ADMIN):
            return False
            
        # Check target user exists
        target_user = self.users.get(target_user_id)
        if not target_user:
            return False
            
        # Create permission
        permission = Permission(
            permission_type=permission_type,
            resource_id=resource_id,
            granted_by=admin_user_id,
            expires_at=expires_at
        )
        
        target_user.permissions.append(permission)
        return True
        
    def revoke_permission(self, admin_user_id: str, target_user_id: str, 
                         permission_type: PermissionType, resource_id: Optional[str] = None) -> bool:
        """Revoke permission from user"""
        # Check admin permissions
        admin_user = self.users.get(admin_user_id)
        if not admin_user or not admin_user.has_permission(PermissionType.SYSTEM_ADMIN):
            return False
            
        # Check target user exists
        target_user = self.users.get(target_user_id)
        if not target_user:
            return False
            
        # Remove matching permissions
        target_user.permissions = [
            perm for perm in target_user.permissions
            if not (perm.permission_type == permission_type and 
                   (resource_id is None or perm.resource_id == resource_id))
        ]
        
        return True
        
    def change_user_role(self, admin_user_id: str, target_user_id: str, new_role: UserRole) -> bool:
        """Change user role"""
        # Check admin permissions
        admin_user = self.users.get(admin_user_id)
        if not admin_user or not admin_user.has_permission(PermissionType.SYSTEM_ADMIN):
            return False
            
        # Check target user exists
        target_user = self.users.get(target_user_id)
        if not target_user:
            return False
            
        # Update role
        target_user.role = new_role
        
        # Clear existing role-based permissions
        target_user.permissions = [
            perm for perm in target_user.permissions
            if perm.granted_by is not None  # Keep manually granted permissions
        ]
        
        # Add new role-based permissions
        for perm_type in self.role_permissions.get(new_role, []):
            permission = Permission(permission_type=perm_type)
            target_user.permissions.append(permission)
            
        return True
        
    def enable_two_factor_auth(self, user_id: str) -> Tuple[str, List[str]]:
        """Enable 2FA for user and return secret and backup codes"""
        user = self.users.get(user_id)
        if not user:
            raise ValueError("User not found")
            
        # Generate 2FA secret
        secret = secrets.token_hex(16)
        
        # Generate backup codes
        backup_codes = [secrets.token_hex(4) for _ in range(10)]
        
        user.two_factor_enabled = True
        user.two_factor_secret = secret
        user.backup_codes = backup_codes
        
        return secret, backup_codes
        
    def disable_two_factor_auth(self, user_id: str) -> bool:
        """Disable 2FA for user"""
        user = self.users.get(user_id)
        if not user:
            return False
            
        user.two_factor_enabled = False
        user.two_factor_secret = None
        user.backup_codes = []
        
        return True
        
    def verify_two_factor_code(self, user_id: str, code: str) -> bool:
        """Verify 2FA code or backup code"""
        user = self.users.get(user_id)
        if not user or not user.two_factor_enabled:
            return False
            
        # Check backup codes first
        if code in user.backup_codes:
            user.backup_codes.remove(code)  # Use backup code only once
            return True
            
        # In production, implement TOTP verification here
        # For now, accept the secret as valid code
        return code == user.two_factor_secret
        
    def get_user_activity(self, user_id: str, limit: int = 100) -> List[Dict[str, any]]:
        """Get user activity log"""
        activities = []
        
        # Get login attempts
        user_logins = [
            attempt for attempt in self.login_attempts
            if attempt.user_id == user_id
        ][-limit:]
        
        for attempt in user_logins:
            activities.append({
                'type': 'login',
                'timestamp': attempt.timestamp,
                'success': attempt.success,
                'ip_address': attempt.ip_address,
                'details': attempt.failure_reason if not attempt.success else 'Successful login'
            })
            
        # Get wallet activities (simplified)
        user_wallets = self.get_user_wallets(user_id)
        for wallet_id in user_wallets:
            wallet = self.wallets.get(wallet_id)
            if wallet:
                for tx in wallet.get_transaction_history(limit=10):
                    activities.append({
                        'type': 'transaction',
                        'timestamp': tx.timestamp,
                        'details': f"Transaction {tx.tx_hash[:8]}... - {tx.amount} {tx.token}",
                        'wallet_id': wallet_id
                    })
                    
        # Sort by timestamp
        activities.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return activities[:limit]
        
    def _record_login_attempt(self, user_identifier: str, ip_address: str, 
                             success: bool, failure_reason: Optional[str] = None):
        """Record login attempt"""
        # Convert username to user_id if needed
        user_id = user_identifier
        if user_identifier in self.username_to_user_id:
            user_id = self.username_to_user_id[user_identifier]
            
        attempt = LoginAttempt(
            user_id=user_id,
            ip_address=ip_address,
            timestamp=int(time.time()),
            success=success,
            failure_reason=failure_reason
        )
        
        self.login_attempts.append(attempt)
        
        # Keep only last 1000 attempts
        if len(self.login_attempts) > 1000:
            self.login_attempts = self.login_attempts[-1000:]
            
    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions"""
        expired_sessions = [
            session_id for session_id, session in self.active_sessions.items()
            if not session.is_valid
        ]
        
        for session_id in expired_sessions:
            self._cleanup_session(session_id)
            
        return len(expired_sessions)
        
    def get_system_stats(self) -> Dict[str, any]:
        """Get system statistics"""
        active_users = sum(1 for user in self.users.values() if user.is_active)
        total_wallets = len(self.wallets)
        active_sessions = len(self.active_sessions)
        
        # Calculate total accounts across all wallets
        total_accounts = sum(len(wallet.accounts) for wallet in self.wallets.values())
        
        # Calculate total transactions
        total_transactions = sum(len(wallet.transactions) for wallet in self.wallets.values())
        
        return {
            'total_users': len(self.users),
            'active_users': active_users,
            'total_wallets': total_wallets,
            'total_accounts': total_accounts,
            'total_transactions': total_transactions,
            'active_sessions': active_sessions,
            'login_attempts_today': len([
                attempt for attempt in self.login_attempts
                if attempt.timestamp > int(time.time()) - 86400
            ])
        }
        
    def export_user_data(self, user_id: str) -> Dict[str, any]:
        """Export user data for backup or compliance"""
        user = self.users.get(user_id)
        if not user:
            return {}
            
        # Export user profile (excluding sensitive data)
        user_data = {
            'user_id': user.user_id,
            'username': user.username,
            'email': user.email,
            'full_name': user.full_name,
            'role': user.role.value,
            'created_at': user.created_at,
            'last_login': user.last_login,
            'is_active': user.is_active,
            'is_verified': user.is_verified,
            'preferences': {
                'default_currency': user.default_currency,
                'timezone': user.timezone,
                'notifications': user.notification_preferences
            }
        }
        
        # Export wallet information
        user_data['wallets'] = []
        for wallet_id in self.get_user_wallets(user_id):
            wallet = self.wallets.get(wallet_id)
            if wallet:
                wallet_info = wallet.get_wallet_info()
                user_data['wallets'].append(wallet_info)
                
        return user_data
        
    def delete_user(self, admin_user_id: str, target_user_id: str) -> bool:
        """Delete user account (admin only)"""
        # Check admin permissions
        admin_user = self.users.get(admin_user_id)
        if not admin_user or not admin_user.has_permission(PermissionType.SYSTEM_ADMIN):
            return False
            
        # Check target user exists
        if target_user_id not in self.users:
            return False
            
        target_user = self.users[target_user_id]
        
        # Logout all sessions
        self.logout_all_sessions(target_user_id)
        
        # Remove from mappings
        if target_user.username in self.username_to_user_id:
            del self.username_to_user_id[target_user.username]
        if target_user.email in self.email_to_user_id:
            del self.email_to_user_id[target_user.email]
            
        # Remove user data
        del self.users[target_user_id]
        if target_user_id in self.user_credentials:
            del self.user_credentials[target_user_id]
        if target_user_id in self.user_wallets:
            del self.user_wallets[target_user_id]
        if target_user_id in self.user_sessions:
            del self.user_sessions[target_user_id]
            
        return True