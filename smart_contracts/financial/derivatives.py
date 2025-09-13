from typing import Dict, List, Optional, Tuple, Union
import time
import math
from dataclasses import dataclass
from enum import Enum
from decimal import Decimal, getcontext

from ..engine import SmartContract

# Set precision for financial calculations
getcontext().prec = 28

class DerivativeType(Enum):
    CALL_OPTION = "CALL_OPTION"
    PUT_OPTION = "PUT_OPTION"
    FUTURE = "FUTURE"
    SWAP = "SWAP"
    FORWARD = "FORWARD"

class OptionStyle(Enum):
    EUROPEAN = "EUROPEAN"  # Can only be exercised at expiration
    AMERICAN = "AMERICAN"  # Can be exercised anytime before expiration

class DerivativeStatus(Enum):
    ACTIVE = "ACTIVE"
    EXERCISED = "EXERCISED"
    EXPIRED = "EXPIRED"
    SETTLED = "SETTLED"
    CANCELLED = "CANCELLED"

class SwapType(Enum):
    INTEREST_RATE = "INTEREST_RATE"
    CURRENCY = "CURRENCY"
    COMMODITY = "COMMODITY"
    CREDIT_DEFAULT = "CREDIT_DEFAULT"

@dataclass
class OptionTerms:
    """Option contract terms"""
    underlying_asset: str  # Asset symbol
    strike_price: int  # Strike price (scaled)
    expiration: int  # Expiration timestamp
    option_type: DerivativeType  # CALL or PUT
    style: OptionStyle  # European or American
    contract_size: int  # Number of units
    premium: int  # Option premium
    settlement_type: str  # "PHYSICAL" or "CASH"

@dataclass
class FutureTerms:
    """Future contract terms"""
    underlying_asset: str
    contract_price: int  # Agreed future price
    expiration: int  # Settlement date
    contract_size: int  # Quantity
    margin_requirement: int  # Initial margin
    maintenance_margin: int  # Maintenance margin
    tick_size: int  # Minimum price movement
    daily_limit: int  # Daily price limit

@dataclass
class SwapTerms:
    """Swap contract terms"""
    swap_type: SwapType
    notional_amount: int  # Notional principal
    fixed_rate: int  # Fixed interest rate (basis points)
    floating_rate_index: str  # Reference rate (e.g., "LIBOR")
    payment_frequency: int  # Payment frequency in days
    start_date: int  # Swap start date
    maturity_date: int  # Swap end date
    day_count_convention: str  # "30/360", "ACT/365", etc.

@dataclass
class DerivativeContract:
    """Base derivative contract"""
    id: str
    contract_type: DerivativeType
    creator: str  # Contract creator
    counterparty: str  # Other party (empty if not matched)
    status: DerivativeStatus
    creation_time: int
    terms: Union[OptionTerms, FutureTerms, SwapTerms]
    collateral_posted: Dict[str, int]  # party -> amount
    margin_calls: List[Dict]  # Margin call history
    settlement_price: int = 0
    pnl: Dict[str, int] = None  # party -> profit/loss

@dataclass
class MarginAccount:
    """Margin account for derivatives trading"""
    owner: str
    balances: Dict[str, int]  # token -> balance
    locked_margin: Dict[str, int]  # contract_id -> locked_amount
    maintenance_margin: Dict[str, int]  # contract_id -> required_margin
    margin_calls: List[Dict]  # Active margin calls
    last_margin_check: int

@dataclass
class PriceData:
    """Price data for underlying assets"""
    asset: str
    price: int
    timestamp: int
    volume: int
    volatility: int  # Implied volatility (basis points)

class DerivativesExchange(SmartContract):
    """Decentralized Derivatives Exchange"""
    
    def __init__(self, owner: str):
        super().__init__()
        
        self.owner = owner
        
        # Core data structures
        self.contracts: Dict[str, DerivativeContract] = {}
        self.margin_accounts: Dict[str, MarginAccount] = {}
        self.contract_counter = 0
        
        # Market data
        self.price_feeds: Dict[str, PriceData] = {}
        self.volatility_surface: Dict[str, Dict[int, Dict[int, int]]] = {}  # asset -> expiry -> strike -> iv
        
        # Order books for derivatives
        self.option_orderbook: Dict[str, List[Dict]] = {}  # option_key -> orders
        self.future_orderbook: Dict[str, List[Dict]] = {}  # future_key -> orders
        
        # Risk management
        self.margin_requirements: Dict[str, int] = {}  # asset -> margin_rate
        self.position_limits: Dict[str, int] = {}  # asset -> max_position
        self.daily_limits: Dict[str, int] = {}  # asset -> daily_limit
        
        # Protocol parameters
        self.trading_fee: int = 10  # 0.1% trading fee
        self.settlement_fee: int = 5  # 0.05% settlement fee
        self.margin_call_threshold: int = 8000  # 80% of maintenance margin
        self.liquidation_threshold: int = 7000  # 70% of maintenance margin
        
        # Statistics
        self.total_volume: Dict[str, int] = {}
        self.open_interest: Dict[str, int] = {}
        self.protocol_fees: Dict[str, int] = {}
        
    def update_price_feed(self, asset: str, price: int, volume: int = 0, volatility: int = 0) -> bool:
        """Update price feed for an asset"""
        caller = self._get_caller()
        if caller != self.owner:
            return False
            
        self.price_feeds[asset] = PriceData(
            asset=asset,
            price=price,
            timestamp=int(time.time()),
            volume=volume,
            volatility=volatility
        )
        
        # Update margin requirements based on new prices
        self._update_margin_requirements()
        
        self._emit_event('PriceFeedUpdated', {
            'asset': asset,
            'price': price,
            'volume': volume,
            'volatility': volatility
        })
        
        return True
        
    def create_margin_account(self) -> bool:
        """Create a margin account for derivatives trading"""
        caller = self._get_caller()
        
        if caller in self.margin_accounts:
            return False  # Account already exists
            
        self.margin_accounts[caller] = MarginAccount(
            owner=caller,
            balances={},
            locked_margin={},
            maintenance_margin={},
            margin_calls=[],
            last_margin_check=int(time.time())
        )
        
        self._emit_event('MarginAccountCreated', {
            'owner': caller
        })
        
        return True
        
    def deposit_margin(self, token: str, amount: int) -> bool:
        """Deposit margin to account"""
        caller = self._get_caller()
        
        if caller not in self.margin_accounts:
            return False
            
        account = self.margin_accounts[caller]
        account.balances[token] = account.balances.get(token, 0) + amount
        
        # In real implementation, transfer tokens from user
        
        self._emit_event('MarginDeposited', {
            'user': caller,
            'token': token,
            'amount': amount
        })
        
        return True
        
    def create_option(self, underlying: str, strike_price: int, expiration: int,
                     option_type: str, style: str, contract_size: int,
                     premium: int, settlement_type: str = "CASH") -> str:
        """Create an option contract"""
        caller = self._get_caller()
        
        if caller not in self.margin_accounts:
            return ""  # Need margin account
            
        # Validate parameters
        if expiration <= int(time.time()):
            return ""  # Invalid expiration
            
        if option_type not in ["CALL_OPTION", "PUT_OPTION"]:
            return ""  # Invalid option type
            
        # Generate contract ID
        self.contract_counter += 1
        contract_id = f"option_{self.contract_counter}_{int(time.time())}"
        
        # Create option terms
        terms = OptionTerms(
            underlying_asset=underlying,
            strike_price=strike_price,
            expiration=expiration,
            option_type=DerivativeType(option_type),
            style=OptionStyle(style),
            contract_size=contract_size,
            premium=premium,
            settlement_type=settlement_type
        )
        
        # Calculate required margin
        margin_required = self._calculate_option_margin(terms)
        
        # Check if user has sufficient margin
        account = self.margin_accounts[caller]
        available_margin = self._get_available_margin(caller)
        
        if available_margin < margin_required:
            return ""  # Insufficient margin
            
        # Create contract
        contract = DerivativeContract(
            id=contract_id,
            contract_type=DerivativeType(option_type),
            creator=caller,
            counterparty="",
            status=DerivativeStatus.ACTIVE,
            creation_time=int(time.time()),
            terms=terms,
            collateral_posted={caller: margin_required},
            margin_calls=[],
            pnl={caller: 0}
        )
        
        self.contracts[contract_id] = contract
        
        # Lock margin
        account.locked_margin[contract_id] = margin_required
        account.maintenance_margin[contract_id] = margin_required
        
        # Add to order book
        option_key = f"{underlying}_{strike_price}_{expiration}_{option_type}"
        if option_key not in self.option_orderbook:
            self.option_orderbook[option_key] = []
            
        self.option_orderbook[option_key].append({
            'contract_id': contract_id,
            'creator': caller,
            'premium': premium,
            'size': contract_size,
            'timestamp': int(time.time())
        })
        
        self._emit_event('OptionCreated', {
            'contract_id': contract_id,
            'creator': caller,
            'underlying': underlying,
            'strike_price': strike_price,
            'expiration': expiration,
            'option_type': option_type,
            'premium': premium,
            'contract_size': contract_size
        })
        
        return contract_id
        
    def create_future(self, underlying: str, contract_price: int, expiration: int,
                     contract_size: int, margin_requirement: int) -> str:
        """Create a futures contract"""
        caller = self._get_caller()
        
        if caller not in self.margin_accounts:
            return ""  # Need margin account
            
        # Generate contract ID
        self.contract_counter += 1
        contract_id = f"future_{self.contract_counter}_{int(time.time())}"
        
        # Create future terms
        terms = FutureTerms(
            underlying_asset=underlying,
            contract_price=contract_price,
            expiration=expiration,
            contract_size=contract_size,
            margin_requirement=margin_requirement,
            maintenance_margin=margin_requirement // 2,  # 50% of initial margin
            tick_size=1,  # Minimum price movement
            daily_limit=contract_price // 10  # 10% daily limit
        )
        
        # Check margin
        account = self.margin_accounts[caller]
        available_margin = self._get_available_margin(caller)
        
        if available_margin < margin_requirement:
            return ""  # Insufficient margin
            
        # Create contract
        contract = DerivativeContract(
            id=contract_id,
            contract_type=DerivativeType.FUTURE,
            creator=caller,
            counterparty="",
            status=DerivativeStatus.ACTIVE,
            creation_time=int(time.time()),
            terms=terms,
            collateral_posted={caller: margin_requirement},
            margin_calls=[],
            pnl={caller: 0}
        )
        
        self.contracts[contract_id] = contract
        
        # Lock margin
        account.locked_margin[contract_id] = margin_requirement
        account.maintenance_margin[contract_id] = terms.maintenance_margin
        
        self._emit_event('FutureCreated', {
            'contract_id': contract_id,
            'creator': caller,
            'underlying': underlying,
            'contract_price': contract_price,
            'expiration': expiration,
            'contract_size': contract_size,
            'margin_requirement': margin_requirement
        })
        
        return contract_id
        
    def create_swap(self, swap_type: str, notional_amount: int, fixed_rate: int,
                   floating_rate_index: str, payment_frequency: int,
                   maturity_days: int) -> str:
        """Create an interest rate swap"""
        caller = self._get_caller()
        
        if caller not in self.margin_accounts:
            return ""  # Need margin account
            
        # Generate contract ID
        self.contract_counter += 1
        contract_id = f"swap_{self.contract_counter}_{int(time.time())}"
        
        current_time = int(time.time())
        
        # Create swap terms
        terms = SwapTerms(
            swap_type=SwapType(swap_type),
            notional_amount=notional_amount,
            fixed_rate=fixed_rate,
            floating_rate_index=floating_rate_index,
            payment_frequency=payment_frequency,
            start_date=current_time,
            maturity_date=current_time + (maturity_days * 86400),
            day_count_convention="ACT/365"
        )
        
        # Calculate margin requirement (typically 1-5% of notional)
        margin_required = (notional_amount * 200) // 10000  # 2% of notional
        
        # Check margin
        available_margin = self._get_available_margin(caller)
        if available_margin < margin_required:
            return ""  # Insufficient margin
            
        # Create contract
        contract = DerivativeContract(
            id=contract_id,
            contract_type=DerivativeType.SWAP,
            creator=caller,
            counterparty="",
            status=DerivativeStatus.ACTIVE,
            creation_time=current_time,
            terms=terms,
            collateral_posted={caller: margin_required},
            margin_calls=[],
            pnl={caller: 0}
        )
        
        self.contracts[contract_id] = contract
        
        # Lock margin
        account = self.margin_accounts[caller]
        account.locked_margin[contract_id] = margin_required
        account.maintenance_margin[contract_id] = margin_required
        
        self._emit_event('SwapCreated', {
            'contract_id': contract_id,
            'creator': caller,
            'swap_type': swap_type,
            'notional_amount': notional_amount,
            'fixed_rate': fixed_rate,
            'floating_rate_index': floating_rate_index,
            'maturity_days': maturity_days
        })
        
        return contract_id
        
    def exercise_option(self, contract_id: str) -> bool:
        """Exercise an option contract"""
        caller = self._get_caller()
        
        if contract_id not in self.contracts:
            return False
            
        contract = self.contracts[contract_id]
        
        # Validate exercise conditions
        if (contract.creator != caller and contract.counterparty != caller):
            return False
            
        if contract.status != DerivativeStatus.ACTIVE:
            return False
            
        if not isinstance(contract.terms, OptionTerms):
            return False
            
        terms = contract.terms
        current_time = int(time.time())
        
        # Check if option can be exercised
        if terms.style == OptionStyle.EUROPEAN and current_time < terms.expiration:
            return False  # European options can only be exercised at expiration
            
        if current_time > terms.expiration:
            return False  # Option has expired
            
        # Get current price
        if terms.underlying_asset not in self.price_feeds:
            return False  # No price feed
            
        current_price = self.price_feeds[terms.underlying_asset].price
        
        # Check if option is in the money
        is_profitable = False
        if terms.option_type == DerivativeType.CALL_OPTION:
            is_profitable = current_price > terms.strike_price
        else:  # PUT_OPTION
            is_profitable = current_price < terms.strike_price
            
        if not is_profitable:
            return False  # Option is out of the money
            
        # Calculate settlement amount
        if terms.option_type == DerivativeType.CALL_OPTION:
            settlement_amount = (current_price - terms.strike_price) * terms.contract_size
        else:  # PUT_OPTION
            settlement_amount = (terms.strike_price - current_price) * terms.contract_size
            
        # Update contract
        contract.status = DerivativeStatus.EXERCISED
        contract.settlement_price = current_price
        
        # Calculate P&L
        if caller == contract.creator:
            contract.pnl[caller] = settlement_amount - terms.premium
            if contract.counterparty:
                contract.pnl[contract.counterparty] = terms.premium - settlement_amount
        else:
            contract.pnl[caller] = terms.premium - settlement_amount
            contract.pnl[contract.creator] = settlement_amount - terms.premium
            
        # Release margins and settle
        self._settle_contract(contract_id)
        
        self._emit_event('OptionExercised', {
            'contract_id': contract_id,
            'exerciser': caller,
            'settlement_price': current_price,
            'settlement_amount': settlement_amount,
            'pnl': contract.pnl.get(caller, 0)
        })
        
        return True
        
    def settle_future(self, contract_id: str) -> bool:
        """Settle a futures contract at expiration"""
        if contract_id not in self.contracts:
            return False
            
        contract = self.contracts[contract_id]
        
        if contract.status != DerivativeStatus.ACTIVE:
            return False
            
        if not isinstance(contract.terms, FutureTerms):
            return False
            
        terms = contract.terms
        current_time = int(time.time())
        
        # Check if contract has expired
        if current_time < terms.expiration:
            return False
            
        # Get settlement price
        if terms.underlying_asset not in self.price_feeds:
            return False
            
        settlement_price = self.price_feeds[terms.underlying_asset].price
        
        # Calculate P&L
        price_diff = settlement_price - terms.contract_price
        settlement_amount = price_diff * terms.contract_size
        
        # Update contract
        contract.status = DerivativeStatus.SETTLED
        contract.settlement_price = settlement_price
        
        # Long position profits if price goes up
        contract.pnl[contract.creator] = settlement_amount
        if contract.counterparty:
            contract.pnl[contract.counterparty] = -settlement_amount
            
        # Settle contract
        self._settle_contract(contract_id)
        
        self._emit_event('FutureSettled', {
            'contract_id': contract_id,
            'settlement_price': settlement_price,
            'contract_price': terms.contract_price,
            'settlement_amount': settlement_amount
        })
        
        return True
        
    def liquidate_position(self, contract_id: str, user: str) -> bool:
        """Liquidate an undercollateralized position"""
        caller = self._get_caller()
        
        if contract_id not in self.contracts:
            return False
            
        if user not in self.margin_accounts:
            return False
            
        # Check if position needs liquidation
        margin_ratio = self._calculate_margin_ratio(user, contract_id)
        
        if margin_ratio > self.liquidation_threshold:
            return False  # Position is adequately collateralized
            
        contract = self.contracts[contract_id]
        
        # Force close position
        if isinstance(contract.terms, FutureTerms):
            # Mark to market and settle
            current_price = self.price_feeds.get(contract.terms.underlying_asset, {}).price
            if current_price:
                price_diff = current_price - contract.terms.contract_price
                pnl = price_diff * contract.terms.contract_size
                
                # Apply liquidation penalty
                liquidation_penalty = abs(pnl) // 10  # 10% penalty
                final_pnl = pnl - liquidation_penalty if pnl > 0 else pnl + liquidation_penalty
                
                contract.pnl[user] = final_pnl
                contract.status = DerivativeStatus.SETTLED
                
        # Release margins
        account = self.margin_accounts[user]
        if contract_id in account.locked_margin:
            del account.locked_margin[contract_id]
        if contract_id in account.maintenance_margin:
            del account.maintenance_margin[contract_id]
            
        self._emit_event('PositionLiquidated', {
            'contract_id': contract_id,
            'user': user,
            'liquidator': caller,
            'margin_ratio': margin_ratio,
            'pnl': contract.pnl.get(user, 0)
        })
        
        return True
        
    def _calculate_option_margin(self, terms: OptionTerms) -> int:
        """Calculate margin requirement for option"""
        # Simplified margin calculation
        # In practice, this would use more sophisticated models
        
        if terms.underlying_asset not in self.price_feeds:
            return terms.premium * 2  # Default margin
            
        underlying_price = self.price_feeds[terms.underlying_asset].price
        
        # For short options, margin is typically:
        # Premium + max(20% of underlying - out-of-money amount, 10% of underlying)
        
        if terms.option_type == DerivativeType.CALL_OPTION:
            otm_amount = max(0, terms.strike_price - underlying_price)
        else:
            otm_amount = max(0, underlying_price - terms.strike_price)
            
        margin_calc1 = (underlying_price * 2000) // 10000 - otm_amount  # 20% - OTM
        margin_calc2 = (underlying_price * 1000) // 10000  # 10%
        
        base_margin = max(margin_calc1, margin_calc2) * terms.contract_size
        
        return terms.premium + base_margin
        
    def _get_available_margin(self, user: str) -> int:
        """Calculate available margin for user"""
        if user not in self.margin_accounts:
            return 0
            
        account = self.margin_accounts[user]
        
        # Sum all token balances (simplified - should use USD values)
        total_balance = sum(account.balances.values())
        total_locked = sum(account.locked_margin.values())
        
        return max(0, total_balance - total_locked)
        
    def _calculate_margin_ratio(self, user: str, contract_id: str) -> int:
        """Calculate current margin ratio for a position"""
        if user not in self.margin_accounts or contract_id not in self.contracts:
            return 0
            
        account = self.margin_accounts[user]
        contract = self.contracts[contract_id]
        
        # Get current margin value
        current_margin = account.balances.get("USD", 0)  # Simplified
        
        # Add unrealized P&L
        unrealized_pnl = self._calculate_unrealized_pnl(contract_id, user)
        effective_margin = current_margin + unrealized_pnl
        
        # Get maintenance margin requirement
        maintenance_required = account.maintenance_margin.get(contract_id, 0)
        
        if maintenance_required == 0:
            return 10000  # 100% if no requirement
            
        return (effective_margin * 10000) // maintenance_required
        
    def _calculate_unrealized_pnl(self, contract_id: str, user: str) -> int:
        """Calculate unrealized P&L for a position"""
        contract = self.contracts[contract_id]
        
        if isinstance(contract.terms, FutureTerms):
            terms = contract.terms
            if terms.underlying_asset in self.price_feeds:
                current_price = self.price_feeds[terms.underlying_asset].price
                price_diff = current_price - terms.contract_price
                
                # Determine position direction
                if user == contract.creator:
                    return price_diff * terms.contract_size  # Long position
                else:
                    return -price_diff * terms.contract_size  # Short position
                    
        elif isinstance(contract.terms, OptionTerms):
            terms = contract.terms
            if terms.underlying_asset in self.price_feeds:
                current_price = self.price_feeds[terms.underlying_asset].price
                
                # Calculate option intrinsic value
                if terms.option_type == DerivativeType.CALL_OPTION:
                    intrinsic_value = max(0, current_price - terms.strike_price)
                else:
                    intrinsic_value = max(0, terms.strike_price - current_price)
                    
                option_value = intrinsic_value * terms.contract_size
                
                # Option buyer's P&L
                if user == contract.creator:
                    return option_value - terms.premium
                else:
                    return terms.premium - option_value
                    
        return 0
        
    def _settle_contract(self, contract_id: str):
        """Settle a derivative contract"""
        contract = self.contracts[contract_id]
        
        # Release locked margins
        for party in [contract.creator, contract.counterparty]:
            if party and party in self.margin_accounts:
                account = self.margin_accounts[party]
                if contract_id in account.locked_margin:
                    del account.locked_margin[contract_id]
                if contract_id in account.maintenance_margin:
                    del account.maintenance_margin[contract_id]
                    
                # Apply P&L to account balance
                pnl = contract.pnl.get(party, 0)
                account.balances["USD"] = account.balances.get("USD", 0) + pnl
                
    def _update_margin_requirements(self):
        """Update margin requirements based on market conditions"""
        current_time = int(time.time())
        
        for user, account in self.margin_accounts.items():
            # Skip if recently checked
            if current_time - account.last_margin_check < 3600:  # 1 hour
                continue
                
            account.last_margin_check = current_time
            
            # Check each position
            for contract_id in list(account.locked_margin.keys()):
                margin_ratio = self._calculate_margin_ratio(user, contract_id)
                
                # Issue margin call if below threshold
                if margin_ratio < self.margin_call_threshold:
                    margin_call = {
                        'contract_id': contract_id,
                        'user': user,
                        'current_ratio': margin_ratio,
                        'required_ratio': self.margin_call_threshold,
                        'timestamp': current_time,
                        'deadline': current_time + 86400  # 24 hours to meet call
                    }
                    
                    account.margin_calls.append(margin_call)
                    
                    self._emit_event('MarginCall', margin_call)
                    
    def get_contract_info(self, contract_id: str) -> Dict[str, any]:
        """Get comprehensive contract information"""
        if contract_id not in self.contracts:
            return {}
            
        contract = self.contracts[contract_id]
        
        base_info = {
            'id': contract.id,
            'type': contract.contract_type.value,
            'creator': contract.creator,
            'counterparty': contract.counterparty,
            'status': contract.status.value,
            'creation_time': contract.creation_time,
            'collateral_posted': dict(contract.collateral_posted),
            'pnl': dict(contract.pnl) if contract.pnl else {}
        }
        
        # Add type-specific information
        if isinstance(contract.terms, OptionTerms):
            terms = contract.terms
            base_info.update({
                'underlying_asset': terms.underlying_asset,
                'strike_price': terms.strike_price,
                'expiration': terms.expiration,
                'option_type': terms.option_type.value,
                'style': terms.style.value,
                'contract_size': terms.contract_size,
                'premium': terms.premium,
                'settlement_type': terms.settlement_type
            })
            
        elif isinstance(contract.terms, FutureTerms):
            terms = contract.terms
            base_info.update({
                'underlying_asset': terms.underlying_asset,
                'contract_price': terms.contract_price,
                'expiration': terms.expiration,
                'contract_size': terms.contract_size,
                'margin_requirement': terms.margin_requirement,
                'maintenance_margin': terms.maintenance_margin
            })
            
        elif isinstance(contract.terms, SwapTerms):
            terms = contract.terms
            base_info.update({
                'swap_type': terms.swap_type.value,
                'notional_amount': terms.notional_amount,
                'fixed_rate': terms.fixed_rate,
                'floating_rate_index': terms.floating_rate_index,
                'payment_frequency': terms.payment_frequency,
                'start_date': terms.start_date,
                'maturity_date': terms.maturity_date
            })
            
        return base_info
        
    def get_user_positions(self, user: str) -> Dict[str, any]:
        """Get all positions for a user"""
        if user not in self.margin_accounts:
            return {}
            
        account = self.margin_accounts[user]
        
        positions = []
        for contract_id in account.locked_margin.keys():
            if contract_id in self.contracts:
                contract_info = self.get_contract_info(contract_id)
                contract_info['unrealized_pnl'] = self._calculate_unrealized_pnl(contract_id, user)
                contract_info['margin_ratio'] = self._calculate_margin_ratio(user, contract_id)
                positions.append(contract_info)
                
        return {
            'user': user,
            'account_balance': dict(account.balances),
            'total_locked_margin': sum(account.locked_margin.values()),
            'available_margin': self._get_available_margin(user),
            'active_positions': positions,
            'margin_calls': account.margin_calls
        }
        
    def get_market_data(self, asset: str) -> Dict[str, any]:
        """Get market data for an asset"""
        if asset not in self.price_feeds:
            return {}
            
        price_data = self.price_feeds[asset]
        
        return {
            'asset': asset,
            'price': price_data.price,
            'timestamp': price_data.timestamp,
            'volume': price_data.volume,
            'volatility': price_data.volatility,
            'open_interest': self.open_interest.get(asset, 0),
            'daily_volume': self.total_volume.get(asset, 0)
        }