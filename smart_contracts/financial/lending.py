from typing import Dict, List, Optional, Tuple
import time
import math
from dataclasses import dataclass
from enum import Enum
from decimal import Decimal, getcontext

from ..engine import SmartContract

# Set precision for financial calculations
getcontext().prec = 28

class LoanStatus(Enum):
    ACTIVE = "ACTIVE"
    REPAID = "REPAID"
    LIQUIDATED = "LIQUIDATED"
    DEFAULTED = "DEFAULTED"

class CollateralStatus(Enum):
    ACTIVE = "ACTIVE"
    LIQUIDATED = "LIQUIDATED"
    WITHDRAWN = "WITHDRAWN"

@dataclass
class LoanTerms:
    """Loan terms structure"""
    principal: int  # Amount borrowed
    collateral_amount: int  # Collateral deposited
    collateral_token: str  # Collateral token address
    loan_token: str  # Borrowed token address
    interest_rate: int  # Annual interest rate in basis points
    duration: int  # Loan duration in seconds
    ltv_ratio: int  # Loan-to-value ratio in basis points (7000 = 70%)
    liquidation_threshold: int  # Liquidation threshold in basis points (8000 = 80%)

@dataclass
class Loan:
    """Loan structure"""
    id: str
    borrower: str
    lender: str
    terms: LoanTerms
    start_time: int
    end_time: int
    status: LoanStatus
    accrued_interest: int = 0
    last_interest_update: int = 0
    repaid_amount: int = 0
    liquidation_price: int = 0  # Price at which loan gets liquidated

@dataclass
class CollateralPosition:
    """Collateral position structure"""
    id: str
    owner: str
    token: str
    amount: int
    locked_amount: int  # Amount locked for loans
    status: CollateralStatus
    deposit_time: int

@dataclass
class InterestRateModel:
    """Interest rate model parameters"""
    base_rate: int  # Base interest rate in basis points
    multiplier: int  # Rate multiplier based on utilization
    jump_multiplier: int  # Rate multiplier after optimal utilization
    optimal_utilization: int  # Optimal utilization rate in basis points

class LendingProtocol(SmartContract):
    """Decentralized Lending Protocol"""
    
    def __init__(self, owner: str):
        super().__init__()
        
        self.owner = owner
        
        # Core data structures
        self.loans: Dict[str, Loan] = {}
        self.collateral_positions: Dict[str, CollateralPosition] = {}
        self.loan_counter = 0
        self.collateral_counter = 0
        
        # User mappings
        self.user_loans: Dict[str, List[str]] = {}  # borrower -> loan_ids
        self.user_collateral: Dict[str, List[str]] = {}  # user -> collateral_ids
        self.lender_loans: Dict[str, List[str]] = {}  # lender -> loan_ids
        
        # Token pools for lending
        self.lending_pools: Dict[str, int] = {}  # token -> available_amount
        self.borrowed_amounts: Dict[str, int] = {}  # token -> borrowed_amount
        self.lender_deposits: Dict[str, Dict[str, int]] = {}  # lender -> token -> amount
        
        # Interest rate models per token
        self.interest_models: Dict[str, InterestRateModel] = {}
        
        # Price feeds (oracle integration)
        self.price_feeds: Dict[str, int] = {}  # token -> price_in_usd (scaled by 10^8)
        
        # Protocol parameters
        self.liquidation_bonus: int = 500  # 5% bonus for liquidators
        self.protocol_fee: int = 100  # 1% protocol fee on interest
        self.min_collateral_ratio: int = 15000  # 150% minimum collateral ratio
        
        # Risk management
        self.max_ltv: Dict[str, int] = {}  # token -> max_ltv_ratio
        self.liquidation_thresholds: Dict[str, int] = {}  # token -> threshold
        
        # Protocol statistics
        self.total_borrowed: Dict[str, int] = {}
        self.total_supplied: Dict[str, int] = {}
        self.protocol_revenue: Dict[str, int] = {}  # token -> revenue_amount
        
    def set_interest_rate_model(self, token: str, base_rate: int, 
                               multiplier: int, jump_multiplier: int, 
                               optimal_utilization: int) -> bool:
        """Set interest rate model for a token"""
        caller = self._get_caller()
        if caller != self.owner:
            return False
            
        self.interest_models[token] = InterestRateModel(
            base_rate=base_rate,
            multiplier=multiplier,
            jump_multiplier=jump_multiplier,
            optimal_utilization=optimal_utilization
        )
        
        self._emit_event('InterestRateModelUpdated', {
            'token': token,
            'base_rate': base_rate,
            'multiplier': multiplier,
            'jump_multiplier': jump_multiplier,
            'optimal_utilization': optimal_utilization
        })
        
        return True
        
    def set_price_feed(self, token: str, price: int) -> bool:
        """Set price feed for a token (oracle function)"""
        caller = self._get_caller()
        if caller != self.owner:
            return False
            
        self.price_feeds[token] = price
        
        self._emit_event('PriceFeedUpdated', {
            'token': token,
            'price': price
        })
        
        return True
        
    def supply(self, token: str, amount: int) -> bool:
        """Supply tokens to the lending pool"""
        caller = self._get_caller()
        
        # In a real implementation, transfer tokens from user
        # For now, assume external transfer handling
        
        # Update lending pool
        self.lending_pools[token] = self.lending_pools.get(token, 0) + amount
        
        # Track lender deposits
        if caller not in self.lender_deposits:
            self.lender_deposits[caller] = {}
        self.lender_deposits[caller][token] = self.lender_deposits[caller].get(token, 0) + amount
        
        # Update statistics
        self.total_supplied[token] = self.total_supplied.get(token, 0) + amount
        
        self._emit_event('Supply', {
            'lender': caller,
            'token': token,
            'amount': amount
        })
        
        return True
        
    def withdraw_supply(self, token: str, amount: int) -> bool:
        """Withdraw supplied tokens from the lending pool"""
        caller = self._get_caller()
        
        # Check if user has enough deposits
        user_deposit = self.lender_deposits.get(caller, {}).get(token, 0)
        if user_deposit < amount:
            return False
            
        # Check if pool has enough liquidity
        available = self.lending_pools.get(token, 0)
        if available < amount:
            return False
            
        # Update balances
        self.lending_pools[token] -= amount
        self.lender_deposits[caller][token] -= amount
        self.total_supplied[token] -= amount
        
        # In a real implementation, transfer tokens to user
        
        self._emit_event('WithdrawSupply', {
            'lender': caller,
            'token': token,
            'amount': amount
        })
        
        return True
        
    def deposit_collateral(self, token: str, amount: int) -> str:
        """Deposit collateral"""
        caller = self._get_caller()
        
        # Generate collateral ID
        self.collateral_counter += 1
        collateral_id = f"collateral_{self.collateral_counter}_{int(time.time())}"
        
        # Create collateral position
        position = CollateralPosition(
            id=collateral_id,
            owner=caller,
            token=token,
            amount=amount,
            locked_amount=0,
            status=CollateralStatus.ACTIVE,
            deposit_time=int(time.time())
        )
        
        self.collateral_positions[collateral_id] = position
        
        # Track user collateral
        if caller not in self.user_collateral:
            self.user_collateral[caller] = []
        self.user_collateral[caller].append(collateral_id)
        
        # In a real implementation, transfer tokens from user
        
        self._emit_event('CollateralDeposited', {
            'user': caller,
            'collateral_id': collateral_id,
            'token': token,
            'amount': amount
        })
        
        return collateral_id
        
    def borrow(self, loan_token: str, amount: int, collateral_id: str, 
              duration_days: int) -> str:
        """Borrow tokens against collateral"""
        caller = self._get_caller()
        
        # Validate collateral
        if collateral_id not in self.collateral_positions:
            return ""
            
        collateral = self.collateral_positions[collateral_id]
        if collateral.owner != caller or collateral.status != CollateralStatus.ACTIVE:
            return ""
            
        # Check if enough liquidity in pool
        available = self.lending_pools.get(loan_token, 0)
        if available < amount:
            return ""
            
        # Calculate collateral value and LTV
        collateral_price = self.price_feeds.get(collateral.token, 0)
        loan_price = self.price_feeds.get(loan_token, 0)
        
        if collateral_price == 0 or loan_price == 0:
            return ""  # No price feed
            
        collateral_value_usd = (collateral.amount * collateral_price) // 10**8
        loan_value_usd = (amount * loan_price) // 10**8
        
        ltv_ratio = (loan_value_usd * 10000) // collateral_value_usd
        max_ltv = self.max_ltv.get(collateral.token, 7000)  # Default 70%
        
        if ltv_ratio > max_ltv:
            return ""  # LTV too high
            
        # Calculate interest rate
        interest_rate = self._calculate_interest_rate(loan_token)
        
        # Generate loan ID
        self.loan_counter += 1
        loan_id = f"loan_{self.loan_counter}_{int(time.time())}"
        
        # Create loan terms
        terms = LoanTerms(
            principal=amount,
            collateral_amount=collateral.amount,
            collateral_token=collateral.token,
            loan_token=loan_token,
            interest_rate=interest_rate,
            duration=duration_days * 86400,  # Convert to seconds
            ltv_ratio=ltv_ratio,
            liquidation_threshold=self.liquidation_thresholds.get(collateral.token, 8000)
        )
        
        # Create loan
        current_time = int(time.time())
        loan = Loan(
            id=loan_id,
            borrower=caller,
            lender="protocol",  # Protocol acts as lender
            terms=terms,
            start_time=current_time,
            end_time=current_time + terms.duration,
            status=LoanStatus.ACTIVE,
            last_interest_update=current_time,
            liquidation_price=self._calculate_liquidation_price(collateral_price, loan_price, terms)
        )
        
        self.loans[loan_id] = loan
        
        # Lock collateral
        collateral.locked_amount = collateral.amount
        
        # Update pool balances
        self.lending_pools[loan_token] -= amount
        self.borrowed_amounts[loan_token] = self.borrowed_amounts.get(loan_token, 0) + amount
        
        # Track user loans
        if caller not in self.user_loans:
            self.user_loans[caller] = []
        self.user_loans[caller].append(loan_id)
        
        # Update statistics
        self.total_borrowed[loan_token] = self.total_borrowed.get(loan_token, 0) + amount
        
        # In a real implementation, transfer borrowed tokens to user
        
        self._emit_event('LoanCreated', {
            'loan_id': loan_id,
            'borrower': caller,
            'loan_token': loan_token,
            'amount': amount,
            'collateral_id': collateral_id,
            'interest_rate': interest_rate,
            'duration': terms.duration
        })
        
        return loan_id
        
    def repay(self, loan_id: str, amount: int) -> bool:
        """Repay loan"""
        caller = self._get_caller()
        
        if loan_id not in self.loans:
            return False
            
        loan = self.loans[loan_id]
        
        if loan.borrower != caller or loan.status != LoanStatus.ACTIVE:
            return False
            
        # Update accrued interest
        self._update_loan_interest(loan_id)
        
        # Calculate total debt
        total_debt = loan.terms.principal + loan.accrued_interest
        remaining_debt = total_debt - loan.repaid_amount
        
        # Determine repayment amount
        repay_amount = min(amount, remaining_debt)
        
        # Update loan
        loan.repaid_amount += repay_amount
        
        # Check if fully repaid
        if loan.repaid_amount >= total_debt:
            loan.status = LoanStatus.REPAID
            
            # Unlock collateral
            for collateral_id in self.user_collateral.get(caller, []):
                if collateral_id in self.collateral_positions:
                    collateral = self.collateral_positions[collateral_id]
                    if collateral.locked_amount > 0:
                        collateral.locked_amount = 0
                        break
                        
        # Update pool balances
        self.lending_pools[loan.terms.loan_token] = self.lending_pools.get(loan.terms.loan_token, 0) + repay_amount
        self.borrowed_amounts[loan.terms.loan_token] -= repay_amount
        
        # Calculate protocol fee
        interest_portion = min(repay_amount, loan.accrued_interest)
        protocol_fee = (interest_portion * self.protocol_fee) // 10000
        self.protocol_revenue[loan.terms.loan_token] = self.protocol_revenue.get(loan.terms.loan_token, 0) + protocol_fee
        
        # In a real implementation, transfer repayment from user
        
        self._emit_event('LoanRepayment', {
            'loan_id': loan_id,
            'borrower': caller,
            'amount': repay_amount,
            'remaining_debt': remaining_debt - repay_amount,
            'status': loan.status.value
        })
        
        return True
        
    def liquidate(self, loan_id: str) -> bool:
        """Liquidate an undercollateralized loan"""
        caller = self._get_caller()
        
        if loan_id not in self.loans:
            return False
            
        loan = self.loans[loan_id]
        
        if loan.status != LoanStatus.ACTIVE:
            return False
            
        # Update interest
        self._update_loan_interest(loan_id)
        
        # Check if loan is liquidatable
        if not self._is_liquidatable(loan):
            return False
            
        # Calculate liquidation amounts
        total_debt = loan.terms.principal + loan.accrued_interest
        collateral_price = self.price_feeds.get(loan.terms.collateral_token, 0)
        loan_price = self.price_feeds.get(loan.terms.loan_token, 0)
        
        # Calculate collateral to seize
        collateral_value = (loan.terms.collateral_amount * collateral_price) // 10**8
        debt_value = (total_debt * loan_price) // 10**8
        
        # Add liquidation bonus
        liquidation_value = debt_value + ((debt_value * self.liquidation_bonus) // 10000)
        collateral_to_seize = min(
            loan.terms.collateral_amount,
            (liquidation_value * 10**8) // collateral_price
        )
        
        # Update loan status
        loan.status = LoanStatus.LIQUIDATED
        
        # Transfer collateral to liquidator
        # In a real implementation, transfer collateral tokens to caller
        
        # Update pool balances
        self.lending_pools[loan.terms.loan_token] = self.lending_pools.get(loan.terms.loan_token, 0) + total_debt
        self.borrowed_amounts[loan.terms.loan_token] -= loan.terms.principal
        
        # Find and update collateral position
        for collateral_id in self.user_collateral.get(loan.borrower, []):
            if collateral_id in self.collateral_positions:
                collateral = self.collateral_positions[collateral_id]
                if collateral.token == loan.terms.collateral_token and collateral.locked_amount > 0:
                    collateral.status = CollateralStatus.LIQUIDATED
                    collateral.locked_amount = 0
                    break
                    
        self._emit_event('LoanLiquidated', {
            'loan_id': loan_id,
            'borrower': loan.borrower,
            'liquidator': caller,
            'debt_amount': total_debt,
            'collateral_seized': collateral_to_seize,
            'liquidation_bonus': (collateral_to_seize * self.liquidation_bonus) // 10000
        })
        
        return True
        
    def _calculate_interest_rate(self, token: str) -> int:
        """Calculate current interest rate for a token"""
        if token not in self.interest_models:
            return 1000  # Default 10% APR
            
        model = self.interest_models[token]
        
        # Calculate utilization rate
        total_supplied = self.total_supplied.get(token, 0)
        total_borrowed = self.total_borrowed.get(token, 0)
        
        if total_supplied == 0:
            return model.base_rate
            
        utilization = (total_borrowed * 10000) // total_supplied
        
        if utilization <= model.optimal_utilization:
            # Below optimal utilization
            rate = model.base_rate + ((utilization * model.multiplier) // 10000)
        else:
            # Above optimal utilization
            excess_utilization = utilization - model.optimal_utilization
            rate = (model.base_rate + 
                   ((model.optimal_utilization * model.multiplier) // 10000) +
                   ((excess_utilization * model.jump_multiplier) // 10000))
                   
        return rate
        
    def _update_loan_interest(self, loan_id: str):
        """Update accrued interest for a loan"""
        loan = self.loans[loan_id]
        current_time = int(time.time())
        
        if loan.last_interest_update >= current_time:
            return
            
        time_elapsed = current_time - loan.last_interest_update
        
        # Calculate interest (compound interest)
        annual_rate = loan.terms.interest_rate / 10000  # Convert from basis points
        rate_per_second = annual_rate / (365 * 24 * 3600)
        
        outstanding_principal = loan.terms.principal + loan.accrued_interest - loan.repaid_amount
        interest = int(outstanding_principal * rate_per_second * time_elapsed)
        
        loan.accrued_interest += interest
        loan.last_interest_update = current_time
        
    def _calculate_liquidation_price(self, collateral_price: int, loan_price: int, terms: LoanTerms) -> int:
        """Calculate the price at which loan becomes liquidatable"""
        # Liquidation occurs when collateral_value / debt_value < liquidation_threshold
        # liquidation_price = (debt_value * liquidation_threshold) / collateral_amount
        debt_value = (terms.principal * loan_price) // 10**8
        threshold_value = (debt_value * terms.liquidation_threshold) // 10000
        liquidation_price = (threshold_value * 10**8) // terms.collateral_amount
        
        return liquidation_price
        
    def _is_liquidatable(self, loan: Loan) -> bool:
        """Check if a loan is liquidatable"""
        collateral_price = self.price_feeds.get(loan.terms.collateral_token, 0)
        loan_price = self.price_feeds.get(loan.terms.loan_token, 0)
        
        if collateral_price == 0 or loan_price == 0:
            return False
            
        total_debt = loan.terms.principal + loan.accrued_interest
        
        collateral_value = (loan.terms.collateral_amount * collateral_price) // 10**8
        debt_value = (total_debt * loan_price) // 10**8
        
        if debt_value == 0:
            return False
            
        collateral_ratio = (collateral_value * 10000) // debt_value
        
        return collateral_ratio < loan.terms.liquidation_threshold
        
    def get_loan_info(self, loan_id: str) -> Dict[str, any]:
        """Get comprehensive loan information"""
        if loan_id not in self.loans:
            return {}
            
        loan = self.loans[loan_id]
        
        # Update interest before returning info
        self._update_loan_interest(loan_id)
        
        total_debt = loan.terms.principal + loan.accrued_interest
        remaining_debt = total_debt - loan.repaid_amount
        
        # Calculate current LTV and health factor
        collateral_price = self.price_feeds.get(loan.terms.collateral_token, 0)
        loan_price = self.price_feeds.get(loan.terms.loan_token, 0)
        
        current_ltv = 0
        health_factor = 0
        
        if collateral_price > 0 and loan_price > 0:
            collateral_value = (loan.terms.collateral_amount * collateral_price) // 10**8
            debt_value = (remaining_debt * loan_price) // 10**8
            
            if debt_value > 0:
                current_ltv = (debt_value * 10000) // collateral_value
                health_factor = (collateral_value * loan.terms.liquidation_threshold) // (debt_value * 10000)
                
        return {
            'id': loan.id,
            'borrower': loan.borrower,
            'status': loan.status.value,
            'principal': loan.terms.principal,
            'accrued_interest': loan.accrued_interest,
            'total_debt': total_debt,
            'remaining_debt': remaining_debt,
            'collateral_amount': loan.terms.collateral_amount,
            'collateral_token': loan.terms.collateral_token,
            'loan_token': loan.terms.loan_token,
            'interest_rate': loan.terms.interest_rate,
            'start_time': loan.start_time,
            'end_time': loan.end_time,
            'current_ltv': current_ltv,
            'liquidation_threshold': loan.terms.liquidation_threshold,
            'health_factor': health_factor,
            'is_liquidatable': self._is_liquidatable(loan)
        }
        
    def get_protocol_stats(self) -> Dict[str, any]:
        """Get protocol statistics"""
        return {
            'total_loans': len(self.loans),
            'active_loans': len([l for l in self.loans.values() if l.status == LoanStatus.ACTIVE]),
            'total_supplied': dict(self.total_supplied),
            'total_borrowed': dict(self.total_borrowed),
            'lending_pools': dict(self.lending_pools),
            'protocol_revenue': dict(self.protocol_revenue),
            'utilization_rates': {
                token: (self.total_borrowed.get(token, 0) * 10000) // max(self.total_supplied.get(token, 1), 1)
                for token in self.total_supplied.keys()
            }
        }