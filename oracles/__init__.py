"""Oracle System Package

This package provides a comprehensive oracle system for the blockchain platform,
including price feeds, data aggregation, oracle management, and dispute resolution.

Key Components:
- PriceFeedManager: Manages price data from multiple sources
- OracleManager: Handles oracle registration, requests, and reputation
- DataSource: External data source integration
- OracleNode: Individual oracle node management
- Dispute resolution system
- Reputation tracking

Features:
- Multi-source price aggregation
- Oracle reputation system
- Dispute resolution mechanism
- Stake-based security
- Real-time data feeds
- Consensus mechanisms
- Performance monitoring
"""

from .price_feed import (
    PriceFeedManager,
    PriceData,
    AggregatedPrice,
    DataSource,
    OracleNode,
    AggregationMethod
)

from .oracle_manager import (
    OracleManager,
    DataRequest,
    OracleResponse,
    Dispute,
    OracleReputation,
    OracleType,
    DataRequestStatus,
    DisputeStatus
)

# Package metadata
__version__ = "1.0.0"
__author__ = "Blockchain Development Team"
__all__ = [
    # Price Feed Components
    "PriceFeedManager",
    "PriceData",
    "AggregatedPrice",
    "DataSource",
    "OracleNode",
    "AggregationMethod",
    
    # Oracle Management Components
    "OracleManager",
    "DataRequest",
    "OracleResponse",
    "Dispute",
    "OracleReputation",
    "OracleType",
    "DataRequestStatus",
    "DisputeStatus",
    
    # Utility Functions
    "create_oracle_system",
    "get_price_feed",
    "validate_oracle_data",
    "calculate_consensus"
]

# Oracle system constants
DEFAULT_MIN_STAKE = 10000  # Minimum stake for oracle registration
DEFAULT_CONSENSUS_THRESHOLD = 66.67  # Percentage for consensus
DEFAULT_REQUEST_TIMEOUT = 3600  # 1 hour in seconds
DEFAULT_MIN_ORACLES = 3  # Minimum oracles for a request
DEFAULT_MAX_ORACLES = 10  # Maximum oracles for a request
DEFAULT_DISPUTE_STAKE_PERCENTAGE = 10  # Percentage of oracle stake for disputes

# Price feed constants
DEFAULT_UPDATE_INTERVAL = 60  # 1 minute
DEFAULT_PRICE_DEVIATION_THRESHOLD = 5.0  # 5% price deviation threshold
DEFAULT_MAX_PRICE_AGE = 300  # 5 minutes max price age

# Supported data sources
SUPPORTED_EXCHANGES = [
    "binance",
    "coinbase",
    "kraken",
    "huobi",
    "okex",
    "bitfinex"
]

# Supported trading pairs
DEFAULT_TRADING_PAIRS = [
    "BTC/USD",
    "ETH/USD",
    "BNB/USD",
    "ADA/USD",
    "SOL/USD",
    "DOT/USD",
    "AVAX/USD",
    "MATIC/USD"
]

def create_oracle_system(min_stake: int = DEFAULT_MIN_STAKE,
                        consensus_threshold: float = DEFAULT_CONSENSUS_THRESHOLD,
                        request_timeout: int = DEFAULT_REQUEST_TIMEOUT) -> tuple:
    """Create a complete oracle system with price feeds and management
    
    Args:
        min_stake: Minimum stake amount for oracle registration
        consensus_threshold: Percentage threshold for consensus
        request_timeout: Default timeout for data requests
        
    Returns:
        Tuple of (OracleManager, PriceFeedManager)
    """
    # Create oracle manager
    oracle_manager = OracleManager(min_stake_amount=min_stake)
    oracle_manager.consensus_threshold = consensus_threshold
    oracle_manager.request_timeout = request_timeout
    
    # Create price feed manager
    price_feed_manager = PriceFeedManager()
    
    # Initialize default data sources
    for exchange in SUPPORTED_EXCHANGES[:3]:  # Start with top 3 exchanges
        try:
            source = DataSource(
                source_id=f"{exchange}_api",
                name=exchange.title(),
                url=f"https://api.{exchange}.com",
                api_key="",  # Would be configured separately
                is_active=True,
                reliability_score=95.0,
                supported_pairs=DEFAULT_TRADING_PAIRS
            )
            price_feed_manager.add_data_source(source)
        except Exception as e:
            print(f"Warning: Could not initialize {exchange} data source: {e}")
    
    # Link price feed manager to oracle manager
    oracle_manager.price_feed_manager = price_feed_manager
    
    return oracle_manager, price_feed_manager

def get_price_feed(symbol: str, oracle_manager: OracleManager = None) -> dict:
    """Get current price feed for a trading pair
    
    Args:
        symbol: Trading pair symbol (e.g., 'BTC/USD')
        oracle_manager: Optional oracle manager instance
        
    Returns:
        Dictionary with price data and metadata
    """
    if oracle_manager is None:
        # Create temporary price feed manager
        price_manager = PriceFeedManager()
    else:
        price_manager = oracle_manager.price_feed_manager
    
    try:
        # Get aggregated price
        aggregated_price = price_manager.get_aggregated_price(symbol)
        
        if aggregated_price:
            return {
                'symbol': symbol,
                'price': str(aggregated_price.price),
                'confidence': str(aggregated_price.confidence),
                'timestamp': aggregated_price.timestamp,
                'source_count': aggregated_price.source_count,
                'method': aggregated_price.aggregation_method.value,
                'deviation': str(aggregated_price.price_deviation),
                'is_stale': aggregated_price.is_stale
            }
        else:
            return {
                'symbol': symbol,
                'error': 'No price data available',
                'timestamp': None,
                'price': None
            }
    except Exception as e:
        return {
            'symbol': symbol,
            'error': str(e),
            'timestamp': None,
            'price': None
        }

def validate_oracle_data(data: dict, oracle_type: OracleType) -> tuple:
    """Validate oracle data based on type
    
    Args:
        data: Data to validate
        oracle_type: Type of oracle data
        
    Returns:
        Tuple of (is_valid: bool, errors: list)
    """
    errors = []
    
    if not isinstance(data, dict):
        errors.append("Data must be a dictionary")
        return False, errors
    
    if oracle_type == OracleType.PRICE_FEED:
        # Validate price feed data
        if 'price' not in data:
            errors.append("Price field is required")
        else:
            try:
                price = float(data['price'])
                if price <= 0:
                    errors.append("Price must be positive")
            except (ValueError, TypeError):
                errors.append("Price must be a valid number")
        
        if 'timestamp' in data:
            try:
                timestamp = int(data['timestamp'])
                import time
                if timestamp > int(time.time()) + 300:  # 5 minutes in future
                    errors.append("Timestamp cannot be too far in the future")
            except (ValueError, TypeError):
                errors.append("Timestamp must be a valid integer")
    
    elif oracle_type == OracleType.WEATHER:
        # Validate weather data
        required_fields = ['temperature', 'location']
        for field in required_fields:
            if field not in data:
                errors.append(f"{field} field is required for weather data")
    
    elif oracle_type == OracleType.SPORTS:
        # Validate sports data
        required_fields = ['event_id', 'result']
        for field in required_fields:
            if field not in data:
                errors.append(f"{field} field is required for sports data")
    
    elif oracle_type == OracleType.RANDOM:
        # Validate random data
        if 'value' not in data:
            errors.append("Value field is required for random data")
        if 'seed' not in data:
            errors.append("Seed field is required for random data")
    
    return len(errors) == 0, errors

def calculate_consensus(responses: list, threshold: float = DEFAULT_CONSENSUS_THRESHOLD) -> dict:
    """Calculate consensus from oracle responses
    
    Args:
        responses: List of oracle responses
        threshold: Consensus threshold percentage
        
    Returns:
        Dictionary with consensus results
    """
    if not responses:
        return {
            'consensus_reached': False,
            'consensus_value': None,
            'consensus_percentage': 0,
            'response_count': 0
        }
    
    # Group similar responses
    from collections import defaultdict
    import json
    import hashlib
    
    response_groups = defaultdict(list)
    
    for response in responses:
        # Create hash of response data for grouping
        if hasattr(response, 'data'):
            data_str = json.dumps(response.data, sort_keys=True)
        else:
            data_str = json.dumps(response, sort_keys=True)
        
        data_hash = hashlib.sha256(data_str.encode()).hexdigest()
        response_groups[data_hash].append(response)
    
    # Find majority group
    if not response_groups:
        return {
            'consensus_reached': False,
            'consensus_value': None,
            'consensus_percentage': 0,
            'response_count': len(responses)
        }
    
    majority_group = max(response_groups.values(), key=len)
    consensus_percentage = (len(majority_group) / len(responses)) * 100
    
    consensus_reached = consensus_percentage >= threshold
    consensus_value = majority_group[0].data if hasattr(majority_group[0], 'data') else majority_group[0]
    
    return {
        'consensus_reached': consensus_reached,
        'consensus_value': consensus_value,
        'consensus_percentage': consensus_percentage,
        'response_count': len(responses),
        'group_count': len(response_groups),
        'majority_group_size': len(majority_group)
    }

# Global oracle system instance (singleton pattern)
_global_oracle_system = None

def get_global_oracle_system():
    """Get or create global oracle system instance"""
    global _global_oracle_system
    if _global_oracle_system is None:
        _global_oracle_system = create_oracle_system()
    return _global_oracle_system

def reset_global_oracle_system():
    """Reset global oracle system (useful for testing)"""
    global _global_oracle_system
    _global_oracle_system = None

# Oracle system health check
def health_check(oracle_manager: OracleManager = None) -> dict:
    """Perform health check on oracle system
    
    Args:
        oracle_manager: Optional oracle manager instance
        
    Returns:
        Dictionary with health status
    """
    if oracle_manager is None:
        oracle_manager, _ = get_global_oracle_system()
    
    try:
        metrics = oracle_manager.get_system_metrics()
        
        # Determine health status
        health_score = 100
        issues = []
        
        # Check active oracles
        if metrics['active_oracles'] < 3:
            health_score -= 30
            issues.append("Insufficient active oracles")
        
        # Check success rate
        if metrics['success_rate'] < 90:
            health_score -= 20
            issues.append("Low request success rate")
        
        # Check pending requests
        if metrics['pending_requests'] > 100:
            health_score -= 15
            issues.append("High number of pending requests")
        
        # Check disputes
        if metrics['open_disputes'] > 10:
            health_score -= 10
            issues.append("High number of open disputes")
        
        # Check average reputation
        if metrics['average_oracle_reputation'] < 70:
            health_score -= 25
            issues.append("Low average oracle reputation")
        
        health_status = "healthy" if health_score >= 80 else "warning" if health_score >= 60 else "critical"
        
        return {
            'status': health_status,
            'health_score': max(0, health_score),
            'issues': issues,
            'metrics': metrics,
            'timestamp': int(__import__('time').time())
        }
        
    except Exception as e:
        return {
            'status': 'error',
            'health_score': 0,
            'issues': [f"Health check failed: {str(e)}"],
            'metrics': {},
            'timestamp': int(__import__('time').time())
        }