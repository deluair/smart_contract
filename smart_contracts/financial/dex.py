from typing import Dict, List, Optional, Tuple
import time
import math
from dataclasses import dataclass
from enum import Enum
from decimal import Decimal, getcontext

from ..engine import SmartContract

# Set precision for financial calculations
getcontext().prec = 28

class OrderType(Enum):
    BUY = "BUY"
    SELL = "SELL"

class OrderStatus(Enum):
    PENDING = "PENDING"
    PARTIALLY_FILLED = "PARTIALLY_FILLED"
    FILLED = "FILLED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"

@dataclass
class Order:
    """Trading order structure"""
    id: str
    trader: str
    token_a: str  # Token to sell
    token_b: str  # Token to buy
    amount_a: int  # Amount to sell
    amount_b: int  # Amount to buy (or minimum to receive)
    order_type: OrderType
    price: int  # Price in token_b per token_a (scaled by 10^18)
    timestamp: int
    expiry: int
    status: OrderStatus = OrderStatus.PENDING
    filled_amount: int = 0
    fee_paid: int = 0

@dataclass
class LiquidityPool:
    """Automated Market Maker liquidity pool"""
    token_a: str
    token_b: str
    reserve_a: int
    reserve_b: int
    total_liquidity: int
    fee_rate: int  # Fee rate in basis points (100 = 1%)
    k_constant: int  # Constant product k = reserve_a * reserve_b
    
class DecentralizedExchange(SmartContract):
    """Decentralized Exchange with AMM and Order Book"""
    
    def __init__(self, owner: str, platform_fee_rate: int = 30):  # 0.3% default fee
        super().__init__()
        
        self.owner = owner
        self.platform_fee_rate = platform_fee_rate  # In basis points
        
        # Order book
        self.orders: Dict[str, Order] = {}
        self.order_counter = 0
        self.user_orders: Dict[str, List[str]] = {}  # user -> order_ids
        
        # AMM Pools
        self.pools: Dict[str, LiquidityPool] = {}  # pool_id -> pool
        self.user_liquidity: Dict[str, Dict[str, int]] = {}  # user -> pool_id -> liquidity_tokens
        
        # Token balances held by the exchange
        self.token_balances: Dict[str, Dict[str, int]] = {}  # user -> token -> amount
        
        # Trading pairs
        self.trading_pairs: Dict[str, Dict[str, any]] = {}  # pair_id -> pair_info
        
        # Fee collection
        self.collected_fees: Dict[str, int] = {}  # token -> amount
        
        # Price oracles (for reference)
        self.price_feeds: Dict[str, int] = {}  # token_pair -> price
        
        # Trading statistics
        self.volume_24h: Dict[str, int] = {}  # token_pair -> volume
        self.last_volume_reset = int(time.time())
        
    def deposit(self, token: str, amount: int) -> bool:
        """Deposit tokens to the exchange"""
        caller = self._get_caller()
        
        # In a real implementation, this would transfer tokens from user's wallet
        # For now, we'll assume the transfer is handled externally
        
        if caller not in self.token_balances:
            self.token_balances[caller] = {}
            
        self.token_balances[caller][token] = self.token_balances[caller].get(token, 0) + amount
        
        self._emit_event('Deposit', {
            'user': caller,
            'token': token,
            'amount': amount
        })
        
        return True
        
    def withdraw(self, token: str, amount: int) -> bool:
        """Withdraw tokens from the exchange"""
        caller = self._get_caller()
        
        if caller not in self.token_balances:
            return False
            
        if self.token_balances[caller].get(token, 0) < amount:
            return False
            
        self.token_balances[caller][token] -= amount
        
        # In a real implementation, this would transfer tokens to user's wallet
        
        self._emit_event('Withdrawal', {
            'user': caller,
            'token': token,
            'amount': amount
        })
        
        return True
        
    def get_balance(self, user: str, token: str) -> int:
        """Get user's token balance on the exchange"""
        return self.token_balances.get(user, {}).get(token, 0)
        
    def create_order(self, token_a: str, token_b: str, amount_a: int, 
                    min_amount_b: int, order_type: OrderType, 
                    expiry_hours: int = 24) -> str:
        """Create a new trading order"""
        caller = self._get_caller()
        
        # Check balance
        if self.get_balance(caller, token_a) < amount_a:
            return ""
            
        # Generate order ID
        self.order_counter += 1
        order_id = f"order_{self.order_counter}_{int(time.time())}"
        
        # Calculate price
        price = (min_amount_b * 10**18) // amount_a if amount_a > 0 else 0
        
        # Create order
        order = Order(
            id=order_id,
            trader=caller,
            token_a=token_a,
            token_b=token_b,
            amount_a=amount_a,
            amount_b=min_amount_b,
            order_type=order_type,
            price=price,
            timestamp=int(time.time()),
            expiry=int(time.time()) + (expiry_hours * 3600)
        )
        
        # Lock tokens
        self.token_balances[caller][token_a] -= amount_a
        
        # Store order
        self.orders[order_id] = order
        
        if caller not in self.user_orders:
            self.user_orders[caller] = []
        self.user_orders[caller].append(order_id)
        
        self._emit_event('OrderCreated', {
            'order_id': order_id,
            'trader': caller,
            'token_a': token_a,
            'token_b': token_b,
            'amount_a': amount_a,
            'min_amount_b': min_amount_b,
            'price': price
        })
        
        # Try to match with existing orders
        self._try_match_order(order_id)
        
        return order_id
        
    def cancel_order(self, order_id: str) -> bool:
        """Cancel an existing order"""
        caller = self._get_caller()
        
        if order_id not in self.orders:
            return False
            
        order = self.orders[order_id]
        
        if order.trader != caller:
            return False
            
        if order.status not in [OrderStatus.PENDING, OrderStatus.PARTIALLY_FILLED]:
            return False
            
        # Return locked tokens
        remaining_amount = order.amount_a - order.filled_amount
        self.token_balances[caller][order.token_a] = self.token_balances[caller].get(order.token_a, 0) + remaining_amount
        
        # Update order status
        order.status = OrderStatus.CANCELLED
        
        self._emit_event('OrderCancelled', {
            'order_id': order_id,
            'trader': caller
        })
        
        return True
        
    def create_liquidity_pool(self, token_a: str, token_b: str, 
                             amount_a: int, amount_b: int, 
                             fee_rate: int = 30) -> str:
        """Create a new AMM liquidity pool"""
        caller = self._get_caller()
        
        # Check balances
        if (self.get_balance(caller, token_a) < amount_a or 
            self.get_balance(caller, token_b) < amount_b):
            return ""
            
        # Generate pool ID
        pool_id = f"{token_a}_{token_b}" if token_a < token_b else f"{token_b}_{token_a}"
        
        if pool_id in self.pools:
            return ""  # Pool already exists
            
        # Calculate initial liquidity tokens (geometric mean)
        initial_liquidity = int(math.sqrt(amount_a * amount_b))
        
        # Create pool
        pool = LiquidityPool(
            token_a=token_a,
            token_b=token_b,
            reserve_a=amount_a,
            reserve_b=amount_b,
            total_liquidity=initial_liquidity,
            fee_rate=fee_rate,
            k_constant=amount_a * amount_b
        )
        
        self.pools[pool_id] = pool
        
        # Lock tokens
        self.token_balances[caller][token_a] -= amount_a
        self.token_balances[caller][token_b] -= amount_b
        
        # Mint liquidity tokens
        if caller not in self.user_liquidity:
            self.user_liquidity[caller] = {}
        self.user_liquidity[caller][pool_id] = initial_liquidity
        
        self._emit_event('PoolCreated', {
            'pool_id': pool_id,
            'creator': caller,
            'token_a': token_a,
            'token_b': token_b,
            'amount_a': amount_a,
            'amount_b': amount_b,
            'liquidity': initial_liquidity
        })
        
        return pool_id
        
    def add_liquidity(self, pool_id: str, amount_a: int, amount_b: int) -> int:
        """Add liquidity to an existing pool"""
        caller = self._get_caller()
        
        if pool_id not in self.pools:
            return 0
            
        pool = self.pools[pool_id]
        
        # Calculate optimal amounts based on current ratio
        ratio_a = (amount_a * pool.reserve_b) // pool.reserve_a
        ratio_b = (amount_b * pool.reserve_a) // pool.reserve_b
        
        # Use the smaller ratio to maintain pool balance
        if ratio_a <= amount_b:
            final_amount_a = amount_a
            final_amount_b = ratio_a
        else:
            final_amount_a = ratio_b
            final_amount_b = amount_b
            
        # Check balances
        if (self.get_balance(caller, pool.token_a) < final_amount_a or
            self.get_balance(caller, pool.token_b) < final_amount_b):
            return 0
            
        # Calculate liquidity tokens to mint
        liquidity_minted = min(
            (final_amount_a * pool.total_liquidity) // pool.reserve_a,
            (final_amount_b * pool.total_liquidity) // pool.reserve_b
        )
        
        # Update pool
        pool.reserve_a += final_amount_a
        pool.reserve_b += final_amount_b
        pool.total_liquidity += liquidity_minted
        pool.k_constant = pool.reserve_a * pool.reserve_b
        
        # Lock tokens
        self.token_balances[caller][pool.token_a] -= final_amount_a
        self.token_balances[caller][pool.token_b] -= final_amount_b
        
        # Mint liquidity tokens
        if caller not in self.user_liquidity:
            self.user_liquidity[caller] = {}
        self.user_liquidity[caller][pool_id] = self.user_liquidity[caller].get(pool_id, 0) + liquidity_minted
        
        self._emit_event('LiquidityAdded', {
            'pool_id': pool_id,
            'provider': caller,
            'amount_a': final_amount_a,
            'amount_b': final_amount_b,
            'liquidity': liquidity_minted
        })
        
        return liquidity_minted
        
    def remove_liquidity(self, pool_id: str, liquidity_amount: int) -> Tuple[int, int]:
        """Remove liquidity from a pool"""
        caller = self._get_caller()
        
        if pool_id not in self.pools:
            return (0, 0)
            
        pool = self.pools[pool_id]
        user_liquidity = self.user_liquidity.get(caller, {}).get(pool_id, 0)
        
        if user_liquidity < liquidity_amount:
            return (0, 0)
            
        # Calculate token amounts to return
        amount_a = (liquidity_amount * pool.reserve_a) // pool.total_liquidity
        amount_b = (liquidity_amount * pool.reserve_b) // pool.total_liquidity
        
        # Update pool
        pool.reserve_a -= amount_a
        pool.reserve_b -= amount_b
        pool.total_liquidity -= liquidity_amount
        pool.k_constant = pool.reserve_a * pool.reserve_b
        
        # Burn liquidity tokens
        self.user_liquidity[caller][pool_id] -= liquidity_amount
        
        # Return tokens
        self.token_balances[caller][pool.token_a] = self.token_balances[caller].get(pool.token_a, 0) + amount_a
        self.token_balances[caller][pool.token_b] = self.token_balances[caller].get(pool.token_b, 0) + amount_b
        
        self._emit_event('LiquidityRemoved', {
            'pool_id': pool_id,
            'provider': caller,
            'amount_a': amount_a,
            'amount_b': amount_b,
            'liquidity': liquidity_amount
        })
        
        return (amount_a, amount_b)
        
    def swap_exact_tokens_for_tokens(self, token_in: str, token_out: str, 
                                   amount_in: int, min_amount_out: int) -> int:
        """Swap exact input tokens for output tokens using AMM"""
        caller = self._get_caller()
        
        # Find pool
        pool_id = f"{token_in}_{token_out}" if token_in < token_out else f"{token_out}_{token_in}"
        
        if pool_id not in self.pools:
            return 0
            
        pool = self.pools[pool_id]
        
        # Check balance
        if self.get_balance(caller, token_in) < amount_in:
            return 0
            
        # Determine which token is A and which is B
        if (pool.token_a == token_in):
            reserve_in = pool.reserve_a
            reserve_out = pool.reserve_b
        else:
            reserve_in = pool.reserve_b
            reserve_out = pool.reserve_a
            
        # Calculate output amount using constant product formula
        # amount_out = (amount_in * reserve_out) / (reserve_in + amount_in)
        # Apply fee
        amount_in_with_fee = amount_in * (10000 - pool.fee_rate) // 10000
        amount_out = (amount_in_with_fee * reserve_out) // (reserve_in + amount_in_with_fee)
        
        if amount_out < min_amount_out:
            return 0
            
        # Update reserves
        if pool.token_a == token_in:
            pool.reserve_a += amount_in
            pool.reserve_b -= amount_out
        else:
            pool.reserve_b += amount_in
            pool.reserve_a -= amount_out
            
        pool.k_constant = pool.reserve_a * pool.reserve_b
        
        # Execute swap
        self.token_balances[caller][token_in] -= amount_in
        self.token_balances[caller][token_out] = self.token_balances[caller].get(token_out, 0) + amount_out
        
        # Collect fees
        fee_amount = amount_in - amount_in_with_fee
        self.collected_fees[token_in] = self.collected_fees.get(token_in, 0) + fee_amount
        
        # Update volume
        pair_key = f"{token_in}_{token_out}"
        self._update_volume(pair_key, amount_in)
        
        self._emit_event('Swap', {
            'trader': caller,
            'token_in': token_in,
            'token_out': token_out,
            'amount_in': amount_in,
            'amount_out': amount_out,
            'fee': fee_amount
        })
        
        return amount_out
        
    def get_amount_out(self, token_in: str, token_out: str, amount_in: int) -> int:
        """Calculate output amount for a given input (quote)"""
        pool_id = f"{token_in}_{token_out}" if token_in < token_out else f"{token_out}_{token_in}"
        
        if pool_id not in self.pools:
            return 0
            
        pool = self.pools[pool_id]
        
        # Determine reserves
        if pool.token_a == token_in:
            reserve_in = pool.reserve_a
            reserve_out = pool.reserve_b
        else:
            reserve_in = pool.reserve_b
            reserve_out = pool.reserve_a
            
        # Calculate output with fee
        amount_in_with_fee = amount_in * (10000 - pool.fee_rate) // 10000
        amount_out = (amount_in_with_fee * reserve_out) // (reserve_in + amount_in_with_fee)
        
        return amount_out
        
    def get_price(self, pool_id: str, token: str) -> float:
        """Get the price of a token in terms of the other token in the pool"""
        if pool_id not in self.pools:
            return 0.0
            
        pool = self.pools[pool_id]
        
        if token == pool.token_a:
            # Price of token_a in terms of token_b
            return pool.reserve_b / pool.reserve_a if pool.reserve_a > 0 else 0.0
        elif token == pool.token_b:
            # Price of token_b in terms of token_a
            return pool.reserve_a / pool.reserve_b if pool.reserve_b > 0 else 0.0
        else:
            return 0.0
        
    def get_pool_info(self, pool_id: str) -> Dict[str, any]:
        """Get pool information"""
        if pool_id not in self.pools:
            return {}
            
        pool = self.pools[pool_id]
        
        # Calculate price
        price_a_in_b = (pool.reserve_b * 10**18) // pool.reserve_a if pool.reserve_a > 0 else 0
        price_b_in_a = (pool.reserve_a * 10**18) // pool.reserve_b if pool.reserve_b > 0 else 0
        
        return {
            'token_a': pool.token_a,
            'token_b': pool.token_b,
            'reserve_a': pool.reserve_a,
            'reserve_b': pool.reserve_b,
            'total_liquidity': pool.total_liquidity,
            'fee_rate': pool.fee_rate,
            'price_a_in_b': price_a_in_b,
            'price_b_in_a': price_b_in_a,
            'k_constant': pool.k_constant
        }
        
    def _try_match_order(self, order_id: str):
        """Try to match order with existing orders"""
        order = self.orders[order_id]
        
        # Find matching orders
        for other_id, other_order in self.orders.items():
            if (other_id != order_id and 
                other_order.status in [OrderStatus.PENDING, OrderStatus.PARTIALLY_FILLED] and
                other_order.token_a == order.token_b and
                other_order.token_b == order.token_a):
                
                # Check if prices match
                if self._can_match_orders(order, other_order):
                    self._execute_trade(order, other_order)
                    
                    if order.status == OrderStatus.FILLED:
                        break
                        
    def _can_match_orders(self, order1: Order, order2: Order) -> bool:
        """Check if two orders can be matched"""
        # For simplicity, match if prices cross
        return order1.price >= order2.price
        
    def _execute_trade(self, order1: Order, order2: Order):
        """Execute trade between two orders"""
        # Calculate trade amounts
        remaining1 = order1.amount_a - order1.filled_amount
        remaining2 = order2.amount_a - order2.filled_amount
        
        trade_amount = min(remaining1, remaining2)
        
        # Calculate exchange amounts
        amount1_to_2 = trade_amount
        amount2_to_1 = (trade_amount * order2.price) // 10**18
        
        # Calculate fees
        fee1 = (amount1_to_2 * self.platform_fee_rate) // 10000
        fee2 = (amount2_to_1 * self.platform_fee_rate) // 10000
        
        # Update order fills
        order1.filled_amount += trade_amount
        order2.filled_amount += trade_amount
        order1.fee_paid += fee1
        order2.fee_paid += fee2
        
        # Transfer tokens
        self.token_balances[order1.trader][order1.token_b] = self.token_balances[order1.trader].get(order1.token_b, 0) + (amount2_to_1 - fee2)
        self.token_balances[order2.trader][order2.token_b] = self.token_balances[order2.trader].get(order2.token_b, 0) + (amount1_to_2 - fee1)
        
        # Collect fees
        self.collected_fees[order1.token_b] = self.collected_fees.get(order1.token_b, 0) + fee2
        self.collected_fees[order2.token_b] = self.collected_fees.get(order2.token_b, 0) + fee1
        
        # Update order status
        if order1.filled_amount >= order1.amount_a:
            order1.status = OrderStatus.FILLED
        else:
            order1.status = OrderStatus.PARTIALLY_FILLED
            
        if order2.filled_amount >= order2.amount_a:
            order2.status = OrderStatus.FILLED
        else:
            order2.status = OrderStatus.PARTIALLY_FILLED
            
        # Update volume
        pair_key = f"{order1.token_a}_{order1.token_b}"
        self._update_volume(pair_key, trade_amount)
        
        self._emit_event('Trade', {
            'order1_id': order1.id,
            'order2_id': order2.id,
            'trader1': order1.trader,
            'trader2': order2.trader,
            'amount': trade_amount,
            'price': order2.price
        })
        
    def _update_volume(self, pair_key: str, amount: int):
        """Update 24h trading volume"""
        current_time = int(time.time())
        
        # Reset volume if 24h passed
        if current_time - self.last_volume_reset > 86400:  # 24 hours
            self.volume_24h = {}
            self.last_volume_reset = current_time
            
        self.volume_24h[pair_key] = self.volume_24h.get(pair_key, 0) + amount
        
    def get_order_book(self, token_a: str, token_b: str) -> Dict[str, List[Dict]]:
        """Get order book for a trading pair"""
        buy_orders = []
        sell_orders = []
        
        for order in self.orders.values():
            if (order.status in [OrderStatus.PENDING, OrderStatus.PARTIALLY_FILLED] and
                order.token_a == token_a and order.token_b == token_b):
                
                order_info = {
                    'id': order.id,
                    'price': order.price,
                    'amount': order.amount_a - order.filled_amount,
                    'timestamp': order.timestamp
                }
                
                if order.order_type == OrderType.BUY:
                    buy_orders.append(order_info)
                else:
                    sell_orders.append(order_info)
                    
        # Sort orders
        buy_orders.sort(key=lambda x: x['price'], reverse=True)  # Highest price first
        sell_orders.sort(key=lambda x: x['price'])  # Lowest price first
        
        return {
            'buy_orders': buy_orders,
            'sell_orders': sell_orders
        }