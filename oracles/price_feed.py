from typing import Dict, List, Optional, Tuple, Union, Callable
import time
import json
import hashlib
import statistics
from dataclasses import dataclass, field
from enum import Enum
from decimal import Decimal, getcontext
import asyncio
import aiohttp
from datetime import datetime, timedelta

from security.cryptography import ECDSAKeyPair
from security.signatures import SignatureData

# Set precision for financial calculations
getcontext().prec = 28

class DataSource(Enum):
    BINANCE = "BINANCE"
    COINBASE = "COINBASE"
    KRAKEN = "KRAKEN"
    HUOBI = "HUOBI"
    BITFINEX = "BITFINEX"
    CHAINLINK = "CHAINLINK"
    BAND_PROTOCOL = "BAND_PROTOCOL"
    CUSTOM = "CUSTOM"

class PriceType(Enum):
    SPOT = "SPOT"
    FUTURES = "FUTURES"
    OPTIONS = "OPTIONS"
    INDEX = "INDEX"
    COMPOSITE = "COMPOSITE"

class DataQuality(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    STALE = "STALE"
    INVALID = "INVALID"

class AggregationMethod(Enum):
    MEDIAN = "MEDIAN"
    MEAN = "MEAN"
    WEIGHTED_AVERAGE = "WEIGHTED_AVERAGE"
    VOLUME_WEIGHTED = "VOLUME_WEIGHTED"
    TIME_WEIGHTED = "TIME_WEIGHTED"

@dataclass
class PriceData:
    """Individual price data point"""
    symbol: str
    price: Decimal
    volume: Decimal
    timestamp: int
    source: DataSource
    price_type: PriceType = PriceType.SPOT
    bid: Optional[Decimal] = None
    ask: Optional[Decimal] = None
    high_24h: Optional[Decimal] = None
    low_24h: Optional[Decimal] = None
    change_24h: Optional[Decimal] = None
    quality: DataQuality = DataQuality.HIGH
    
    @property
    def age_seconds(self) -> int:
        """Age of data in seconds"""
        return int(time.time()) - self.timestamp
        
    @property
    def is_stale(self, max_age: int = 300) -> bool:
        """Check if data is stale (default 5 minutes)"""
        return self.age_seconds > max_age
        
    @property
    def spread(self) -> Optional[Decimal]:
        """Calculate bid-ask spread"""
        if self.bid and self.ask:
            return self.ask - self.bid
        return None
        
    @property
    def spread_percentage(self) -> Optional[Decimal]:
        """Calculate spread as percentage of mid price"""
        spread = self.spread
        if spread and self.bid and self.ask:
            mid_price = (self.bid + self.ask) / 2
            return (spread / mid_price) * 100
        return None

@dataclass
class AggregatedPrice:
    """Aggregated price from multiple sources"""
    symbol: str
    price: Decimal
    confidence: Decimal  # 0-100
    timestamp: int
    sources: List[DataSource]
    method: AggregationMethod
    source_count: int
    price_variance: Decimal
    volume_weighted: bool = False
    
    # Statistical data
    min_price: Optional[Decimal] = None
    max_price: Optional[Decimal] = None
    std_deviation: Optional[Decimal] = None
    
@dataclass
class OracleNode:
    """Oracle node information"""
    node_id: str
    address: str
    public_key: str
    reputation: Decimal  # 0-100
    stake_amount: int
    is_active: bool
    last_update: int
    total_updates: int
    successful_updates: int
    failed_updates: int
    supported_pairs: List[str] = field(default_factory=list)
    
    @property
    def success_rate(self) -> Decimal:
        """Calculate success rate percentage"""
        if self.total_updates == 0:
            return Decimal('0')
        return Decimal(self.successful_updates) / Decimal(self.total_updates) * 100
        
    @property
    def is_reliable(self) -> bool:
        """Check if node is reliable (>95% success rate, reputation >80)"""
        return self.success_rate >= 95 and self.reputation >= 80

class PriceFeedManager:
    """Manages price feeds from multiple sources"""
    
    def __init__(self):
        self.price_data: Dict[str, Dict[DataSource, PriceData]] = {}  # symbol -> source -> data
        self.aggregated_prices: Dict[str, AggregatedPrice] = {}  # symbol -> aggregated price
        self.data_sources: Dict[DataSource, Dict[str, any]] = {}
        self.update_callbacks: List[Callable] = []
        
        # Configuration
        self.max_price_age = 300  # 5 minutes
        self.min_sources_required = 3
        self.max_price_deviation = Decimal('5.0')  # 5% max deviation
        
        # Initialize data sources
        self._initialize_data_sources()
        
    def _initialize_data_sources(self):
        """Initialize data source configurations"""
        self.data_sources = {
            DataSource.BINANCE: {
                'base_url': 'https://api.binance.com/api/v3',
                'weight': Decimal('1.0'),
                'rate_limit': 1200,  # requests per minute
                'supported_pairs': ['BTCUSDT', 'ETHUSDT', 'ADAUSDT', 'DOTUSDT']
            },
            DataSource.COINBASE: {
                'base_url': 'https://api.pro.coinbase.com',
                'weight': Decimal('1.0'),
                'rate_limit': 600,
                'supported_pairs': ['BTC-USD', 'ETH-USD', 'ADA-USD', 'DOT-USD']
            },
            DataSource.KRAKEN: {
                'base_url': 'https://api.kraken.com/0/public',
                'weight': Decimal('0.8'),
                'rate_limit': 300,
                'supported_pairs': ['XBTUSD', 'ETHUSD', 'ADAUSD', 'DOTUSD']
            }
        }
        
    async def fetch_price_data(self, symbol: str, sources: Optional[List[DataSource]] = None) -> Dict[DataSource, PriceData]:
        """Fetch price data from multiple sources"""
        if sources is None:
            sources = list(self.data_sources.keys())
            
        tasks = []
        for source in sources:
            if source in self.data_sources:
                task = self._fetch_from_source(symbol, source)
                tasks.append(task)
                
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        price_data = {}
        for i, result in enumerate(results):
            if isinstance(result, PriceData):
                price_data[sources[i]] = result
                
        return price_data
        
    async def _fetch_from_source(self, symbol: str, source: DataSource) -> Optional[PriceData]:
        """Fetch price data from a specific source"""
        try:
            if source == DataSource.BINANCE:
                return await self._fetch_binance_price(symbol)
            elif source == DataSource.COINBASE:
                return await self._fetch_coinbase_price(symbol)
            elif source == DataSource.KRAKEN:
                return await self._fetch_kraken_price(symbol)
            else:
                return None
        except Exception as e:
            print(f"Error fetching from {source}: {e}")
            return None
            
    async def _fetch_binance_price(self, symbol: str) -> Optional[PriceData]:
        """Fetch price from Binance API"""
        url = f"{self.data_sources[DataSource.BINANCE]['base_url']}/ticker/24hr"
        params = {'symbol': symbol.replace('-', '')}
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return PriceData(
                        symbol=symbol,
                        price=Decimal(data['lastPrice']),
                        volume=Decimal(data['volume']),
                        timestamp=int(time.time()),
                        source=DataSource.BINANCE,
                        bid=Decimal(data['bidPrice']),
                        ask=Decimal(data['askPrice']),
                        high_24h=Decimal(data['highPrice']),
                        low_24h=Decimal(data['lowPrice']),
                        change_24h=Decimal(data['priceChangePercent'])
                    )
        return None
        
    async def _fetch_coinbase_price(self, symbol: str) -> Optional[PriceData]:
        """Fetch price from Coinbase API"""
        url = f"{self.data_sources[DataSource.COINBASE]['base_url']}/products/{symbol}/ticker"
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return PriceData(
                        symbol=symbol,
                        price=Decimal(data['price']),
                        volume=Decimal(data['volume']),
                        timestamp=int(time.time()),
                        source=DataSource.COINBASE,
                        bid=Decimal(data['bid']),
                        ask=Decimal(data['ask'])
                    )
        return None
        
    async def _fetch_kraken_price(self, symbol: str) -> Optional[PriceData]:
        """Fetch price from Kraken API"""
        # Convert symbol format for Kraken
        kraken_symbol = symbol.replace('-', '')
        url = f"{self.data_sources[DataSource.KRAKEN]['base_url']}/Ticker"
        params = {'pair': kraken_symbol}
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    if 'result' in data and kraken_symbol in data['result']:
                        ticker = data['result'][kraken_symbol]
                        return PriceData(
                            symbol=symbol,
                            price=Decimal(ticker['c'][0]),  # Last trade price
                            volume=Decimal(ticker['v'][1]),  # 24h volume
                            timestamp=int(time.time()),
                            source=DataSource.KRAKEN,
                            bid=Decimal(ticker['b'][0]),
                            ask=Decimal(ticker['a'][0]),
                            high_24h=Decimal(ticker['h'][1]),
                            low_24h=Decimal(ticker['l'][1])
                        )
        return None
        
    def update_price_data(self, symbol: str, source_data: Dict[DataSource, PriceData]):
        """Update price data for a symbol"""
        if symbol not in self.price_data:
            self.price_data[symbol] = {}
            
        # Update data from sources
        for source, data in source_data.items():
            if data and not data.is_stale(self.max_price_age):
                self.price_data[symbol][source] = data
                
        # Remove stale data
        self._cleanup_stale_data(symbol)
        
        # Aggregate prices
        aggregated = self.aggregate_prices(symbol)
        if aggregated:
            self.aggregated_prices[symbol] = aggregated
            
            # Notify callbacks
            for callback in self.update_callbacks:
                try:
                    callback(symbol, aggregated)
                except Exception as e:
                    print(f"Error in callback: {e}")
                    
    def aggregate_prices(self, symbol: str, method: AggregationMethod = AggregationMethod.MEDIAN) -> Optional[AggregatedPrice]:
        """Aggregate prices from multiple sources"""
        if symbol not in self.price_data:
            return None
            
        source_data = self.price_data[symbol]
        valid_data = [data for data in source_data.values() if not data.is_stale(self.max_price_age)]
        
        if len(valid_data) < self.min_sources_required:
            return None
            
        # Filter outliers
        valid_data = self._filter_outliers(valid_data)
        
        if not valid_data:
            return None
            
        prices = [data.price for data in valid_data]
        volumes = [data.volume for data in valid_data]
        sources = [data.source for data in valid_data]
        
        # Calculate aggregated price based on method
        if method == AggregationMethod.MEDIAN:
            aggregated_price = Decimal(str(statistics.median(prices)))
        elif method == AggregationMethod.MEAN:
            aggregated_price = sum(prices) / len(prices)
        elif method == AggregationMethod.WEIGHTED_AVERAGE:
            aggregated_price = self._weighted_average(valid_data)
        elif method == AggregationMethod.VOLUME_WEIGHTED:
            aggregated_price = self._volume_weighted_average(valid_data)
        else:
            aggregated_price = Decimal(str(statistics.median(prices)))
            
        # Calculate confidence and variance
        confidence = self._calculate_confidence(valid_data)
        variance = self._calculate_variance(prices, aggregated_price)
        
        return AggregatedPrice(
            symbol=symbol,
            price=aggregated_price,
            confidence=confidence,
            timestamp=int(time.time()),
            sources=sources,
            method=method,
            source_count=len(valid_data),
            price_variance=variance,
            min_price=min(prices),
            max_price=max(prices),
            std_deviation=Decimal(str(statistics.stdev(prices))) if len(prices) > 1 else Decimal('0')
        )
        
    def _filter_outliers(self, data_points: List[PriceData]) -> List[PriceData]:
        """Filter out price outliers using IQR method"""
        if len(data_points) < 3:
            return data_points
            
        prices = [float(data.price) for data in data_points]
        q1 = statistics.quantiles(prices, n=4)[0]
        q3 = statistics.quantiles(prices, n=4)[2]
        iqr = q3 - q1
        
        lower_bound = q1 - 1.5 * iqr
        upper_bound = q3 + 1.5 * iqr
        
        filtered_data = [
            data for data in data_points
            if lower_bound <= float(data.price) <= upper_bound
        ]
        
        return filtered_data if filtered_data else data_points
        
    def _weighted_average(self, data_points: List[PriceData]) -> Decimal:
        """Calculate weighted average based on source reliability"""
        total_weight = Decimal('0')
        weighted_sum = Decimal('0')
        
        for data in data_points:
            weight = self.data_sources[data.source]['weight']
            weighted_sum += data.price * weight
            total_weight += weight
            
        return weighted_sum / total_weight if total_weight > 0 else Decimal('0')
        
    def _volume_weighted_average(self, data_points: List[PriceData]) -> Decimal:
        """Calculate volume-weighted average price"""
        total_volume = sum(data.volume for data in data_points)
        
        if total_volume == 0:
            return sum(data.price for data in data_points) / len(data_points)
            
        weighted_sum = sum(data.price * data.volume for data in data_points)
        return weighted_sum / total_volume
        
    def _calculate_confidence(self, data_points: List[PriceData]) -> Decimal:
        """Calculate confidence score based on data quality and consistency"""
        if not data_points:
            return Decimal('0')
            
        # Base confidence on number of sources
        source_score = min(len(data_points) / 5, 1) * 40  # Max 40 points for sources
        
        # Consistency score based on price variance
        prices = [data.price for data in data_points]
        if len(prices) > 1:
            avg_price = sum(prices) / len(prices)
            max_deviation = max(abs(price - avg_price) / avg_price for price in prices)
            consistency_score = max(0, (1 - float(max_deviation)) * 40)  # Max 40 points
        else:
            consistency_score = 40
            
        # Freshness score
        avg_age = sum(data.age_seconds for data in data_points) / len(data_points)
        freshness_score = max(0, (1 - avg_age / self.max_price_age) * 20)  # Max 20 points
        
        return Decimal(str(source_score + consistency_score + freshness_score))
        
    def _calculate_variance(self, prices: List[Decimal], avg_price: Decimal) -> Decimal:
        """Calculate price variance"""
        if len(prices) <= 1:
            return Decimal('0')
            
        variance_sum = sum((price - avg_price) ** 2 for price in prices)
        return variance_sum / len(prices)
        
    def _cleanup_stale_data(self, symbol: str):
        """Remove stale data for a symbol"""
        if symbol in self.price_data:
            self.price_data[symbol] = {
                source: data for source, data in self.price_data[symbol].items()
                if not data.is_stale(self.max_price_age)
            }
            
    def get_latest_price(self, symbol: str) -> Optional[AggregatedPrice]:
        """Get latest aggregated price for a symbol"""
        return self.aggregated_prices.get(symbol)
        
    def get_price_history(self, symbol: str, hours: int = 24) -> List[AggregatedPrice]:
        """Get price history for a symbol (simplified implementation)"""
        # In a real implementation, this would query a time-series database
        current_price = self.get_latest_price(symbol)
        if current_price:
            return [current_price]  # Simplified - return current price only
        return []
        
    def add_update_callback(self, callback: Callable):
        """Add callback for price updates"""
        self.update_callbacks.append(callback)
        
    def remove_update_callback(self, callback: Callable):
        """Remove price update callback"""
        if callback in self.update_callbacks:
            self.update_callbacks.remove(callback)
            
    def get_supported_symbols(self) -> List[str]:
        """Get list of supported trading symbols"""
        symbols = set()
        for source_config in self.data_sources.values():
            symbols.update(source_config.get('supported_pairs', []))
        return list(symbols)
        
    def get_data_source_status(self) -> Dict[DataSource, Dict[str, any]]:
        """Get status of all data sources"""
        status = {}
        for source, config in self.data_sources.items():
            status[source] = {
                'active': True,  # Simplified - would check actual connectivity
                'last_update': int(time.time()),
                'supported_pairs': len(config.get('supported_pairs', [])),
                'rate_limit': config.get('rate_limit', 0),
                'weight': config.get('weight', 1.0)
            }
        return status
        
    async def start_price_updates(self, symbols: List[str], interval: int = 30):
        """Start continuous price updates"""
        while True:
            try:
                for symbol in symbols:
                    source_data = await self.fetch_price_data(symbol)
                    self.update_price_data(symbol, source_data)
                    
                await asyncio.sleep(interval)
            except Exception as e:
                print(f"Error in price updates: {e}")
                await asyncio.sleep(interval)
                
    def calculate_price_impact(self, symbol: str, trade_size: Decimal) -> Optional[Decimal]:
        """Calculate estimated price impact for a trade"""
        current_price = self.get_latest_price(symbol)
        if not current_price:
            return None
            
        # Simplified price impact calculation
        # In reality, this would consider order book depth
        base_impact = trade_size / Decimal('1000000')  # 0.1% per 1M units
        volatility_multiplier = current_price.std_deviation / current_price.price if current_price.std_deviation else Decimal('0.01')
        
        return base_impact * (1 + volatility_multiplier) * 100  # Return as percentage
        
    def get_market_summary(self) -> Dict[str, any]:
        """Get overall market summary"""
        total_symbols = len(self.aggregated_prices)
        high_confidence_count = sum(
            1 for price in self.aggregated_prices.values()
            if price.confidence >= 80
        )
        
        avg_confidence = (
            sum(price.confidence for price in self.aggregated_prices.values()) / total_symbols
            if total_symbols > 0 else 0
        )
        
        return {
            'total_symbols': total_symbols,
            'high_confidence_symbols': high_confidence_count,
            'average_confidence': float(avg_confidence),
            'active_sources': len(self.data_sources),
            'last_update': int(time.time())
        }