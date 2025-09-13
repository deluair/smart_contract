from typing import Dict, Optional, List
import time
from dataclasses import dataclass
from decimal import Decimal, getcontext

from ..engine import SmartContract

# Set precision for financial calculations
getcontext().prec = 28

@dataclass
class TokenInfo:
    """Token information structure"""
    name: str
    symbol: str
    decimals: int
    total_supply: int
    owner: str
    mintable: bool = True
    burnable: bool = True
    pausable: bool = True

class ERC20Token(SmartContract):
    """ERC-20 compatible token contract with financial market features"""
    
    def __init__(self, name: str, symbol: str, decimals: int = 18, 
                 initial_supply: int = 0, owner: str = ""):
        super().__init__()
        
        # Token metadata
        self.name = name
        self.symbol = symbol
        self.decimals = decimals
        self.total_supply = initial_supply
        self.owner = owner
        
        # State variables
        self.balances: Dict[str, int] = {}
        self.allowances: Dict[str, Dict[str, int]] = {}  # owner -> spender -> amount
        self.frozen_accounts: Dict[str, bool] = {}
        
        # Financial features
        self.is_paused = False
        self.mintable = True
        self.burnable = True
        
        # Advanced features
        self.transfer_fees: Dict[str, int] = {}  # address -> fee percentage (basis points)
        self.blacklisted: Dict[str, bool] = {}
        self.whitelisted: Dict[str, bool] = {}
        self.require_whitelist = False
        
        # Dividend and staking
        self.dividend_per_token = 0
        self.last_dividend_points: Dict[str, int] = {}
        self.staked_balances: Dict[str, int] = {}
        self.staking_rewards_rate = 0  # Annual percentage rate in basis points
        self.last_staking_update: Dict[str, int] = {}
        
        # Initialize owner balance
        if initial_supply > 0 and owner:
            self.balances[owner] = initial_supply
            
    def balance_of(self, account: str) -> int:
        """Get token balance of account"""
        return self.balances.get(account, 0)
        
    def allowance(self, owner: str, spender: str) -> int:
        """Get allowance amount"""
        return self.allowances.get(owner, {}).get(spender, 0)
        
    def transfer(self, to: str, amount: int) -> bool:
        """Transfer tokens"""
        from_address = self._get_caller()
        return self._transfer(from_address, to, amount)
        
    def transfer_from(self, from_address: str, to: str, amount: int) -> bool:
        """Transfer tokens from approved account"""
        spender = self._get_caller()
        
        # Check allowance
        allowed = self.allowance(from_address, spender)
        if allowed < amount:
            self._emit_event('TransferFailed', {
                'from': from_address,
                'to': to,
                'amount': amount,
                'reason': 'Insufficient allowance'
            })
            return False
            
        # Update allowance
        if from_address not in self.allowances:
            self.allowances[from_address] = {}
        self.allowances[from_address][spender] = allowed - amount
        
        return self._transfer(from_address, to, amount)
        
    def approve(self, spender: str, amount: int) -> bool:
        """Approve spender to transfer tokens"""
        owner = self._get_caller()
        
        if owner not in self.allowances:
            self.allowances[owner] = {}
            
        self.allowances[owner][spender] = amount
        
        self._emit_event('Approval', {
            'owner': owner,
            'spender': spender,
            'amount': amount
        })
        
        return True
        
    def increase_allowance(self, spender: str, added_value: int) -> bool:
        """Increase allowance"""
        owner = self._get_caller()
        current_allowance = self.allowance(owner, spender)
        return self.approve(spender, current_allowance + added_value)
        
    def decrease_allowance(self, spender: str, subtracted_value: int) -> bool:
        """Decrease allowance"""
        owner = self._get_caller()
        current_allowance = self.allowance(owner, spender)
        
        if current_allowance < subtracted_value:
            return False
            
        return self.approve(spender, current_allowance - subtracted_value)
        
    def mint(self, to: str, amount: int) -> bool:
        """Mint new tokens"""
        caller = self._get_caller()
        
        # Only owner can mint
        if caller != self.owner:
            return False
            
        if not self.mintable:
            return False
            
        if self.is_paused:
            return False
            
        # Update balances
        self.balances[to] = self.balances.get(to, 0) + amount
        self.total_supply += amount
        
        self._emit_event('Transfer', {
            'from': '0x0',
            'to': to,
            'amount': amount
        })
        
        self._emit_event('Mint', {
            'to': to,
            'amount': amount,
            'total_supply': self.total_supply
        })
        
        return True
        
    def burn(self, amount: int) -> bool:
        """Burn tokens from caller's balance"""
        caller = self._get_caller()
        return self.burn_from(caller, amount)
        
    def burn_from(self, from_address: str, amount: int) -> bool:
        """Burn tokens from specified address"""
        caller = self._get_caller()
        
        if not self.burnable:
            return False
            
        if self.is_paused:
            return False
            
        # Check if caller has permission
        if caller != from_address and caller != self.owner:
            # Check allowance
            allowed = self.allowance(from_address, caller)
            if allowed < amount:
                return False
            # Update allowance
            self.allowances[from_address][caller] = allowed - amount
            
        # Check balance
        if self.balances.get(from_address, 0) < amount:
            return False
            
        # Update balances
        self.balances[from_address] -= amount
        self.total_supply -= amount
        
        self._emit_event('Transfer', {
            'from': from_address,
            'to': '0x0',
            'amount': amount
        })
        
        self._emit_event('Burn', {
            'from': from_address,
            'amount': amount,
            'total_supply': self.total_supply
        })
        
        return True
        
    def pause(self) -> bool:
        """Pause token transfers"""
        caller = self._get_caller()
        if caller != self.owner:
            return False
            
        self.is_paused = True
        self._emit_event('Paused', {'by': caller})
        return True
        
    def unpause(self) -> bool:
        """Unpause token transfers"""
        caller = self._get_caller()
        if caller != self.owner:
            return False
            
        self.is_paused = False
        self._emit_event('Unpaused', {'by': caller})
        return True
        
    def freeze_account(self, account: str) -> bool:
        """Freeze an account"""
        caller = self._get_caller()
        if caller != self.owner:
            return False
            
        self.frozen_accounts[account] = True
        self._emit_event('AccountFrozen', {'account': account})
        return True
        
    def unfreeze_account(self, account: str) -> bool:
        """Unfreeze an account"""
        caller = self._get_caller()
        if caller != self.owner:
            return False
            
        self.frozen_accounts[account] = False
        self._emit_event('AccountUnfrozen', {'account': account})
        return True
        
    def set_transfer_fee(self, account: str, fee_basis_points: int) -> bool:
        """Set transfer fee for account (in basis points, 100 = 1%)"""
        caller = self._get_caller()
        if caller != self.owner:
            return False
            
        if fee_basis_points > 10000:  # Max 100%
            return False
            
        self.transfer_fees[account] = fee_basis_points
        self._emit_event('TransferFeeSet', {
            'account': account,
            'fee_basis_points': fee_basis_points
        })
        return True
        
    def distribute_dividends(self, total_amount: int) -> bool:
        """Distribute dividends to token holders"""
        caller = self._get_caller()
        if caller != self.owner:
            return False
            
        if self.total_supply == 0:
            return False
            
        # Calculate dividend per token
        dividend_per_token = (total_amount * 10**18) // self.total_supply
        self.dividend_per_token += dividend_per_token
        
        self._emit_event('DividendsDistributed', {
            'total_amount': total_amount,
            'dividend_per_token': dividend_per_token
        })
        
        return True
        
    def claim_dividends(self) -> int:
        """Claim pending dividends"""
        caller = self._get_caller()
        balance = self.balance_of(caller)
        
        if balance == 0:
            return 0
            
        last_points = self.last_dividend_points.get(caller, 0)
        pending_dividends = ((self.dividend_per_token - last_points) * balance) // 10**18
        
        if pending_dividends > 0:
            self.last_dividend_points[caller] = self.dividend_per_token
            
            # Transfer dividends (assuming they're in the same token)
            self.balances[caller] = self.balances.get(caller, 0) + pending_dividends
            
            self._emit_event('DividendsClaimed', {
                'account': caller,
                'amount': pending_dividends
            })
            
        return pending_dividends
        
    def stake(self, amount: int) -> bool:
        """Stake tokens for rewards"""
        caller = self._get_caller()
        
        if self.balance_of(caller) < amount:
            return False
            
        # Update staking rewards before staking
        self._update_staking_rewards(caller)
        
        # Transfer tokens to staking
        self.balances[caller] -= amount
        self.staked_balances[caller] = self.staked_balances.get(caller, 0) + amount
        self.last_staking_update[caller] = int(time.time())
        
        self._emit_event('Staked', {
            'account': caller,
            'amount': amount
        })
        
        return True
        
    def unstake(self, amount: int) -> bool:
        """Unstake tokens"""
        caller = self._get_caller()
        
        if self.staked_balances.get(caller, 0) < amount:
            return False
            
        # Update staking rewards before unstaking
        self._update_staking_rewards(caller)
        
        # Transfer tokens back
        self.staked_balances[caller] -= amount
        self.balances[caller] = self.balances.get(caller, 0) + amount
        
        self._emit_event('Unstaked', {
            'account': caller,
            'amount': amount
        })
        
        return True
        
    def get_staked_balance(self, account: str) -> int:
        """Get staked balance"""
        return self.staked_balances.get(account, 0)
        
    def _transfer(self, from_address: str, to: str, amount: int) -> bool:
        """Internal transfer function"""
        # Check if paused
        if self.is_paused:
            return False
            
        # Check frozen accounts
        if self.frozen_accounts.get(from_address, False) or self.frozen_accounts.get(to, False):
            return False
            
        # Check blacklist
        if self.blacklisted.get(from_address, False) or self.blacklisted.get(to, False):
            return False
            
        # Check whitelist if required
        if self.require_whitelist:
            if not (self.whitelisted.get(from_address, False) and self.whitelisted.get(to, False)):
                return False
                
        # Check balance
        if self.balances.get(from_address, 0) < amount:
            return False
            
        # Calculate fees
        fee = 0
        fee_rate = self.transfer_fees.get(from_address, 0)
        if fee_rate > 0:
            fee = (amount * fee_rate) // 10000
            
        # Update dividend points before transfer
        self._update_dividend_points(from_address)
        self._update_dividend_points(to)
        
        # Perform transfer
        self.balances[from_address] -= amount
        self.balances[to] = self.balances.get(to, 0) + (amount - fee)
        
        # Handle fees (send to owner)
        if fee > 0:
            self.balances[self.owner] = self.balances.get(self.owner, 0) + fee
            
        self._emit_event('Transfer', {
            'from': from_address,
            'to': to,
            'amount': amount - fee,
            'fee': fee
        })
        
        return True
        
    def _update_dividend_points(self, account: str):
        """Update dividend points for account"""
        if account not in self.last_dividend_points:
            self.last_dividend_points[account] = self.dividend_per_token
            
    def _update_staking_rewards(self, account: str):
        """Update staking rewards for account"""
        if account not in self.last_staking_update:
            self.last_staking_update[account] = int(time.time())
            return
            
        staked_amount = self.staked_balances.get(account, 0)
        if staked_amount == 0:
            return
            
        time_elapsed = int(time.time()) - self.last_staking_update[account]
        if time_elapsed > 0 and self.staking_rewards_rate > 0:
            # Calculate rewards (annual rate converted to per-second)
            annual_rate = self.staking_rewards_rate / 10000  # Convert from basis points
            rewards = (staked_amount * annual_rate * time_elapsed) // (365 * 24 * 3600)
            
            if rewards > 0:
                self.balances[account] = self.balances.get(account, 0) + rewards
                self._emit_event('StakingRewards', {
                    'account': account,
                    'rewards': rewards
                })
                
        self.last_staking_update[account] = int(time.time())
        
    def get_token_info(self) -> Dict[str, any]:
        """Get comprehensive token information"""
        return {
            'name': self.name,
            'symbol': self.symbol,
            'decimals': self.decimals,
            'total_supply': self.total_supply,
            'owner': self.owner,
            'is_paused': self.is_paused,
            'mintable': self.mintable,
            'burnable': self.burnable,
            'dividend_per_token': self.dividend_per_token,
            'staking_rewards_rate': self.staking_rewards_rate
        }