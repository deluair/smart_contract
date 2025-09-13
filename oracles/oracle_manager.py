from typing import Dict, List, Optional, Set, Tuple, Union, Callable
import time
import json
import hashlib
import secrets
from dataclasses import dataclass, field
from enum import Enum
from decimal import Decimal, getcontext
import asyncio
from collections import defaultdict

from .price_feed import PriceFeedManager, PriceData, AggregatedPrice, DataSource, OracleNode
from security.cryptography import ECDSAKeyPair, CryptoUtils
from security.signatures import SignatureData, TransactionSigner
from blockchain.consensus.pos import Validator

# Set precision for financial calculations
getcontext().prec = 28

class OracleType(Enum):
    PRICE_FEED = "PRICE_FEED"
    WEATHER = "WEATHER"
    SPORTS = "SPORTS"
    RANDOM = "RANDOM"
    COMPUTATION = "COMPUTATION"
    CROSS_CHAIN = "CROSS_CHAIN"
    CUSTOM = "CUSTOM"

class DataRequestStatus(Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    DISPUTED = "DISPUTED"
    CANCELLED = "CANCELLED"

class DisputeStatus(Enum):
    OPEN = "OPEN"
    UNDER_REVIEW = "UNDER_REVIEW"
    RESOLVED = "RESOLVED"
    REJECTED = "REJECTED"

@dataclass
class DataRequest:
    """Oracle data request"""
    request_id: str
    requester: str
    oracle_type: OracleType
    data_specification: Dict[str, any]
    reward_amount: int
    deadline: int
    min_responses: int
    max_responses: int
    created_at: int
    status: DataRequestStatus = DataRequestStatus.PENDING
    assigned_oracles: List[str] = field(default_factory=list)
    responses: List['OracleResponse'] = field(default_factory=list)
    final_result: Optional[Dict[str, any]] = None
    
    @property
    def is_expired(self) -> bool:
        return int(time.time()) > self.deadline
        
    @property
    def has_sufficient_responses(self) -> bool:
        valid_responses = [r for r in self.responses if r.is_valid]
        return len(valid_responses) >= self.min_responses

@dataclass
class OracleResponse:
    """Oracle response to a data request"""
    response_id: str
    request_id: str
    oracle_id: str
    data: Dict[str, any]
    confidence: Decimal  # 0-100
    timestamp: int
    signature: str
    gas_used: int = 0
    is_valid: bool = True
    validation_errors: List[str] = field(default_factory=list)
    
@dataclass
class Dispute:
    """Oracle dispute"""
    dispute_id: str
    request_id: str
    response_id: str
    challenger: str
    reason: str
    evidence: Dict[str, any]
    stake_amount: int
    created_at: int
    status: DisputeStatus = DisputeStatus.OPEN
    resolution: Optional[str] = None
    resolved_at: Optional[int] = None
    resolved_by: Optional[str] = None

@dataclass
class OracleReputation:
    """Oracle reputation tracking"""
    oracle_id: str
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    disputed_requests: int = 0
    average_response_time: Decimal = Decimal('0')
    accuracy_score: Decimal = Decimal('100')  # 0-100
    reliability_score: Decimal = Decimal('100')  # 0-100
    stake_amount: int = 0
    rewards_earned: int = 0
    penalties_paid: int = 0
    last_activity: int = 0
    
    @property
    def success_rate(self) -> Decimal:
        if self.total_requests == 0:
            return Decimal('100')
        return (Decimal(self.successful_requests) / Decimal(self.total_requests)) * 100
        
    @property
    def overall_score(self) -> Decimal:
        """Calculate overall reputation score"""
        weights = {
            'accuracy': Decimal('0.4'),
            'reliability': Decimal('0.3'),
            'success_rate': Decimal('0.2'),
            'stake': Decimal('0.1')
        }
        
        # Normalize stake score (assuming max stake of 1M tokens)
        stake_score = min(Decimal(self.stake_amount) / Decimal('1000000'), 1) * 100
        
        return (
            self.accuracy_score * weights['accuracy'] +
            self.reliability_score * weights['reliability'] +
            self.success_rate * weights['success_rate'] +
            stake_score * weights['stake']
        )

class OracleManager:
    """Comprehensive Oracle Management System"""
    
    def __init__(self, min_stake_amount: int = 10000):
        self.min_stake_amount = min_stake_amount
        
        # Oracle management
        self.oracle_nodes: Dict[str, OracleNode] = {}
        self.oracle_reputations: Dict[str, OracleReputation] = {}
        self.oracle_stakes: Dict[str, int] = {}  # oracle_id -> staked_amount
        
        # Request management
        self.data_requests: Dict[str, DataRequest] = {}
        self.oracle_responses: Dict[str, OracleResponse] = {}
        self.pending_requests: Set[str] = set()
        
        # Dispute management
        self.disputes: Dict[str, Dispute] = {}
        self.dispute_validators: List[str] = []  # List of validator addresses
        
        # Price feed integration
        self.price_feed_manager = PriceFeedManager()
        
        # Security
        self.crypto_utils = CryptoUtils()
        self.transaction_signer = TransactionSigner()
        
        # Configuration
        self.request_timeout = 3600  # 1 hour default
        self.min_oracle_reputation = Decimal('70')
        self.dispute_stake_percentage = Decimal('10')  # 10% of oracle stake
        self.consensus_threshold = Decimal('66.67')  # 66.67% consensus required
        
        # Callbacks
        self.request_callbacks: List[Callable] = []
        self.response_callbacks: List[Callable] = []
        
    def register_oracle(self, oracle_address: str, public_key: str, 
                       stake_amount: int, supported_types: List[OracleType]) -> str:
        """Register a new oracle node"""
        if stake_amount < self.min_stake_amount:
            raise ValueError(f"Minimum stake amount is {self.min_stake_amount}")
            
        oracle_id = f"oracle_{hashlib.sha256(oracle_address.encode()).hexdigest()[:16]}"
        
        # Check if oracle already exists
        if oracle_id in self.oracle_nodes:
            raise ValueError("Oracle already registered")
            
        # Create oracle node
        oracle_node = OracleNode(
            node_id=oracle_id,
            address=oracle_address,
            public_key=public_key,
            reputation=Decimal('100'),  # Start with perfect reputation
            stake_amount=stake_amount,
            is_active=True,
            last_update=int(time.time()),
            total_updates=0,
            successful_updates=0,
            failed_updates=0,
            supported_pairs=[oracle_type.value for oracle_type in supported_types]
        )
        
        # Create reputation tracking
        reputation = OracleReputation(
            oracle_id=oracle_id,
            stake_amount=stake_amount,
            last_activity=int(time.time())
        )
        
        # Store oracle data
        self.oracle_nodes[oracle_id] = oracle_node
        self.oracle_reputations[oracle_id] = reputation
        self.oracle_stakes[oracle_id] = stake_amount
        
        return oracle_id
        
    def unregister_oracle(self, oracle_id: str, oracle_address: str) -> bool:
        """Unregister an oracle node"""
        if oracle_id not in self.oracle_nodes:
            return False
            
        oracle = self.oracle_nodes[oracle_id]
        if oracle.address != oracle_address:
            return False
            
        # Check for pending requests
        pending_count = sum(
            1 for request in self.data_requests.values()
            if oracle_id in request.assigned_oracles and request.status == DataRequestStatus.IN_PROGRESS
        )
        
        if pending_count > 0:
            raise ValueError(f"Oracle has {pending_count} pending requests")
            
        # Deactivate oracle
        oracle.is_active = False
        
        # Return stake (in a real implementation, this would transfer tokens)
        stake_amount = self.oracle_stakes.get(oracle_id, 0)
        del self.oracle_stakes[oracle_id]
        
        return True
        
    def create_data_request(self, requester: str, oracle_type: OracleType,
                           data_spec: Dict[str, any], reward_amount: int,
                           deadline: Optional[int] = None, min_responses: int = 3,
                           max_responses: int = 10) -> str:
        """Create a new data request"""
        request_id = f"req_{secrets.token_hex(16)}"
        
        if deadline is None:
            deadline = int(time.time()) + self.request_timeout
            
        request = DataRequest(
            request_id=request_id,
            requester=requester,
            oracle_type=oracle_type,
            data_specification=data_spec,
            reward_amount=reward_amount,
            deadline=deadline,
            min_responses=min_responses,
            max_responses=max_responses,
            created_at=int(time.time())
        )
        
        # Assign suitable oracles
        assigned_oracles = self._assign_oracles(request)
        request.assigned_oracles = assigned_oracles
        
        if not assigned_oracles:
            raise ValueError("No suitable oracles available")
            
        # Store request
        self.data_requests[request_id] = request
        self.pending_requests.add(request_id)
        
        # Update request status
        request.status = DataRequestStatus.IN_PROGRESS
        
        # Notify callbacks
        for callback in self.request_callbacks:
            try:
                callback(request)
            except Exception as e:
                print(f"Error in request callback: {e}")
                
        return request_id
        
    def _assign_oracles(self, request: DataRequest) -> List[str]:
        """Assign suitable oracles to a request"""
        suitable_oracles = []
        
        for oracle_id, oracle in self.oracle_nodes.items():
            if not oracle.is_active:
                continue
                
            # Check if oracle supports the request type
            if request.oracle_type.value not in oracle.supported_pairs:
                continue
                
            # Check reputation
            reputation = self.oracle_reputations.get(oracle_id)
            if reputation and reputation.overall_score < self.min_oracle_reputation:
                continue
                
            # Check stake amount
            if self.oracle_stakes.get(oracle_id, 0) < self.min_stake_amount:
                continue
                
            suitable_oracles.append(oracle_id)
            
        # Sort by reputation and select top oracles
        suitable_oracles.sort(
            key=lambda oid: self.oracle_reputations[oid].overall_score,
            reverse=True
        )
        
        return suitable_oracles[:request.max_responses]
        
    def submit_oracle_response(self, oracle_id: str, request_id: str,
                              data: Dict[str, any], confidence: Decimal,
                              private_key: str) -> str:
        """Submit oracle response to a data request"""
        if request_id not in self.data_requests:
            raise ValueError("Request not found")
            
        request = self.data_requests[request_id]
        
        # Validate oracle assignment
        if oracle_id not in request.assigned_oracles:
            raise ValueError("Oracle not assigned to this request")
            
        # Check if request is still active
        if request.status != DataRequestStatus.IN_PROGRESS:
            raise ValueError("Request is not active")
            
        if request.is_expired:
            raise ValueError("Request has expired")
            
        # Check if oracle already responded
        existing_response = next(
            (r for r in request.responses if r.oracle_id == oracle_id),
            None
        )
        if existing_response:
            raise ValueError("Oracle already responded to this request")
            
        # Create response
        response_id = f"resp_{secrets.token_hex(16)}"
        
        # Sign the response
        response_data = {
            'request_id': request_id,
            'oracle_id': oracle_id,
            'data': data,
            'confidence': str(confidence),
            'timestamp': int(time.time())
        }
        
        signature = self._sign_response(response_data, private_key)
        
        response = OracleResponse(
            response_id=response_id,
            request_id=request_id,
            oracle_id=oracle_id,
            data=data,
            confidence=confidence,
            timestamp=int(time.time()),
            signature=signature
        )
        
        # Validate response
        self._validate_response(response, request)
        
        # Store response
        self.oracle_responses[response_id] = response
        request.responses.append(response)
        
        # Update oracle reputation
        self._update_oracle_activity(oracle_id)
        
        # Check if we have enough responses
        if request.has_sufficient_responses:
            self._process_request_completion(request)
            
        # Notify callbacks
        for callback in self.response_callbacks:
            try:
                callback(response)
            except Exception as e:
                print(f"Error in response callback: {e}")
                
        return response_id
        
    def _sign_response(self, response_data: Dict[str, any], private_key: str) -> str:
        """Sign oracle response"""
        # Create message hash
        message = json.dumps(response_data, sort_keys=True)
        
        # Sign with oracle's private key
        key_pair = ECDSAKeyPair.from_private_key_bytes(bytes.fromhex(private_key))
        oracle_address = key_pair.get_address()
        
        # Add key pair to signer if not already present
        if oracle_address not in self.transaction_signer.key_pairs:
            self.transaction_signer.add_key_pair(oracle_address, key_pair)
        
        # Sign the message
        signature = self.transaction_signer.sign_message(message, oracle_address)
        
        return signature
        
    def _validate_response(self, response: OracleResponse, request: DataRequest):
        """Validate oracle response"""
        errors = []
        
        # Check confidence range
        if not (0 <= response.confidence <= 100):
            errors.append("Confidence must be between 0 and 100")
            
        # Check data format based on oracle type
        if request.oracle_type == OracleType.PRICE_FEED:
            if 'price' not in response.data:
                errors.append("Price data must include 'price' field")
            try:
                Decimal(str(response.data.get('price', 0)))
            except:
                errors.append("Price must be a valid number")
                
        # Check timestamp freshness
        if response.timestamp < int(time.time()) - 300:  # 5 minutes
            errors.append("Response timestamp is too old")
            
        # Verify signature (simplified)
        oracle = self.oracle_nodes.get(response.oracle_id)
        if oracle:
            # In a real implementation, verify the signature against oracle's public key
            pass
            
        if errors:
            response.is_valid = False
            response.validation_errors = errors
            
    def _process_request_completion(self, request: DataRequest):
        """Process completed data request"""
        valid_responses = [r for r in request.responses if r.is_valid]
        
        if len(valid_responses) < request.min_responses:
            request.status = DataRequestStatus.FAILED
            return
            
        # Aggregate responses based on oracle type
        if request.oracle_type == OracleType.PRICE_FEED:
            final_result = self._aggregate_price_responses(valid_responses)
        else:
            final_result = self._aggregate_generic_responses(valid_responses)
            
        request.final_result = final_result
        request.status = DataRequestStatus.COMPLETED
        
        # Remove from pending
        self.pending_requests.discard(request.request_id)
        
        # Distribute rewards
        self._distribute_rewards(request, valid_responses)
        
        # Update oracle reputations
        self._update_oracle_reputations(request, valid_responses)
        
    def _aggregate_price_responses(self, responses: List[OracleResponse]) -> Dict[str, any]:
        """Aggregate price feed responses"""
        prices = []
        total_confidence = Decimal('0')
        
        for response in responses:
            price = Decimal(str(response.data.get('price', 0)))
            confidence = response.confidence
            
            # Weight by confidence
            weighted_price = price * (confidence / 100)
            prices.append(weighted_price)
            total_confidence += confidence
            
        if not prices:
            return {'error': 'No valid price data'}
            
        # Calculate weighted average
        avg_confidence = total_confidence / len(responses)
        weighted_avg_price = sum(prices) / len(prices) * (100 / avg_confidence) if avg_confidence > 0 else Decimal('0')
        
        # Calculate consensus metrics
        raw_prices = [Decimal(str(r.data.get('price', 0))) for r in responses]
        price_variance = self._calculate_variance(raw_prices, weighted_avg_price)
        
        return {
            'price': str(weighted_avg_price),
            'confidence': str(avg_confidence),
            'response_count': len(responses),
            'variance': str(price_variance),
            'consensus_reached': price_variance < Decimal('0.01')  # 1% variance threshold
        }
        
    def _aggregate_generic_responses(self, responses: List[OracleResponse]) -> Dict[str, any]:
        """Aggregate generic oracle responses using majority consensus"""
        # Group responses by data content
        response_groups = defaultdict(list)
        
        for response in responses:
            data_hash = hashlib.sha256(json.dumps(response.data, sort_keys=True).encode()).hexdigest()
            response_groups[data_hash].append(response)
            
        # Find majority consensus
        majority_group = max(response_groups.values(), key=len)
        consensus_percentage = (len(majority_group) / len(responses)) * 100
        
        if consensus_percentage >= self.consensus_threshold:
            # Use majority response
            representative_response = majority_group[0]
            avg_confidence = sum(r.confidence for r in majority_group) / len(majority_group)
            
            return {
                'data': representative_response.data,
                'confidence': str(avg_confidence),
                'consensus_percentage': str(consensus_percentage),
                'response_count': len(responses),
                'consensus_reached': True
            }
        else:
            return {
                'error': 'No consensus reached',
                'consensus_percentage': str(consensus_percentage),
                'required_threshold': str(self.consensus_threshold),
                'response_count': len(responses),
                'consensus_reached': False
            }
            
    def _calculate_variance(self, values: List[Decimal], mean: Decimal) -> Decimal:
        """Calculate variance of values"""
        if len(values) <= 1:
            return Decimal('0')
            
        variance_sum = sum((value - mean) ** 2 for value in values)
        return variance_sum / len(values)
        
    def _distribute_rewards(self, request: DataRequest, valid_responses: List[OracleResponse]):
        """Distribute rewards to oracles"""
        if not valid_responses:
            return
            
        # Calculate reward per oracle
        base_reward = request.reward_amount // len(valid_responses)
        
        for response in valid_responses:
            oracle_id = response.oracle_id
            
            # Bonus for high confidence
            confidence_bonus = int(base_reward * (response.confidence / 100) * 0.1)
            total_reward = base_reward + confidence_bonus
            
            # Update oracle reputation
            reputation = self.oracle_reputations.get(oracle_id)
            if reputation:
                reputation.rewards_earned += total_reward
                
            # In a real implementation, transfer tokens to oracle
            
    def _update_oracle_reputations(self, request: DataRequest, valid_responses: List[OracleResponse]):
        """Update oracle reputations based on performance"""
        for response in valid_responses:
            oracle_id = response.oracle_id
            reputation = self.oracle_reputations.get(oracle_id)
            
            if not reputation:
                continue
                
            reputation.total_requests += 1
            
            if response.is_valid:
                reputation.successful_requests += 1
                
                # Update accuracy based on consensus
                if request.final_result and request.final_result.get('consensus_reached'):
                    # Reward for being part of consensus
                    reputation.accuracy_score = min(reputation.accuracy_score + Decimal('0.1'), Decimal('100'))
                else:
                    # Small penalty for not reaching consensus
                    reputation.accuracy_score = max(reputation.accuracy_score - Decimal('0.05'), Decimal('0'))
            else:
                reputation.failed_requests += 1
                # Penalty for invalid response
                reputation.accuracy_score = max(reputation.accuracy_score - Decimal('1'), Decimal('0'))
                
            # Update response time
            response_time = response.timestamp - request.created_at
            if reputation.average_response_time == 0:
                reputation.average_response_time = Decimal(response_time)
            else:
                # Moving average
                reputation.average_response_time = (
                    reputation.average_response_time * Decimal('0.9') +
                    Decimal(response_time) * Decimal('0.1')
                )
                
            reputation.last_activity = int(time.time())
            
    def _update_oracle_activity(self, oracle_id: str):
        """Update oracle activity metrics"""
        oracle = self.oracle_nodes.get(oracle_id)
        if oracle:
            oracle.last_update = int(time.time())
            oracle.total_updates += 1
            
    def create_dispute(self, challenger: str, request_id: str, response_id: str,
                      reason: str, evidence: Dict[str, any], stake_amount: int) -> str:
        """Create a dispute against an oracle response"""
        if request_id not in self.data_requests:
            raise ValueError("Request not found")
            
        if response_id not in self.oracle_responses:
            raise ValueError("Response not found")
            
        response = self.oracle_responses[response_id]
        oracle_stake = self.oracle_stakes.get(response.oracle_id, 0)
        min_dispute_stake = int(oracle_stake * self.dispute_stake_percentage / 100)
        
        if stake_amount < min_dispute_stake:
            raise ValueError(f"Minimum dispute stake is {min_dispute_stake}")
            
        dispute_id = f"dispute_{secrets.token_hex(16)}"
        
        dispute = Dispute(
            dispute_id=dispute_id,
            request_id=request_id,
            response_id=response_id,
            challenger=challenger,
            reason=reason,
            evidence=evidence,
            stake_amount=stake_amount,
            created_at=int(time.time())
        )
        
        self.disputes[dispute_id] = dispute
        
        # Mark request as disputed
        request = self.data_requests[request_id]
        if request.status == DataRequestStatus.COMPLETED:
            request.status = DataRequestStatus.DISPUTED
            
        return dispute_id
        
    def resolve_dispute(self, dispute_id: str, resolver: str, resolution: str) -> bool:
        """Resolve a dispute (admin/validator only)"""
        if dispute_id not in self.disputes:
            return False
            
        if resolver not in self.dispute_validators:
            return False
            
        dispute = self.disputes[dispute_id]
        if dispute.status != DisputeStatus.OPEN:
            return False
            
        dispute.status = DisputeStatus.RESOLVED
        dispute.resolution = resolution
        dispute.resolved_at = int(time.time())
        dispute.resolved_by = resolver
        
        # Apply penalties or rewards based on resolution
        response = self.oracle_responses[dispute.response_id]
        oracle_id = response.oracle_id
        reputation = self.oracle_reputations.get(oracle_id)
        
        if "invalid" in resolution.lower():
            # Penalize oracle
            if reputation:
                reputation.disputed_requests += 1
                reputation.accuracy_score = max(reputation.accuracy_score - Decimal('5'), Decimal('0'))
                reputation.penalties_paid += dispute.stake_amount
                
            # Reward challenger (return stake + oracle penalty)
            # In real implementation, transfer tokens
            
        else:
            # Penalize challenger (forfeit stake to oracle)
            if reputation:
                reputation.rewards_earned += dispute.stake_amount
                
        return True
        
    def get_oracle_performance(self, oracle_id: str) -> Optional[Dict[str, any]]:
        """Get comprehensive oracle performance metrics"""
        if oracle_id not in self.oracle_nodes:
            return None
            
        oracle = self.oracle_nodes[oracle_id]
        reputation = self.oracle_reputations.get(oracle_id)
        
        if not reputation:
            return None
            
        return {
            'oracle_id': oracle_id,
            'address': oracle.address,
            'is_active': oracle.is_active,
            'reputation_score': str(reputation.overall_score),
            'accuracy_score': str(reputation.accuracy_score),
            'reliability_score': str(reputation.reliability_score),
            'success_rate': str(reputation.success_rate),
            'total_requests': reputation.total_requests,
            'successful_requests': reputation.successful_requests,
            'failed_requests': reputation.failed_requests,
            'disputed_requests': reputation.disputed_requests,
            'average_response_time': str(reputation.average_response_time),
            'stake_amount': reputation.stake_amount,
            'rewards_earned': reputation.rewards_earned,
            'penalties_paid': reputation.penalties_paid,
            'last_activity': reputation.last_activity
        }
        
    def get_request_status(self, request_id: str) -> Optional[Dict[str, any]]:
        """Get data request status and results"""
        if request_id not in self.data_requests:
            return None
            
        request = self.data_requests[request_id]
        
        return {
            'request_id': request_id,
            'requester': request.requester,
            'oracle_type': request.oracle_type.value,
            'status': request.status.value,
            'created_at': request.created_at,
            'deadline': request.deadline,
            'is_expired': request.is_expired,
            'assigned_oracles': request.assigned_oracles,
            'response_count': len(request.responses),
            'valid_response_count': len([r for r in request.responses if r.is_valid]),
            'min_responses': request.min_responses,
            'has_sufficient_responses': request.has_sufficient_responses,
            'final_result': request.final_result,
            'reward_amount': request.reward_amount
        }
        
    def get_system_metrics(self) -> Dict[str, any]:
        """Get overall oracle system metrics"""
        active_oracles = sum(1 for oracle in self.oracle_nodes.values() if oracle.is_active)
        total_requests = len(self.data_requests)
        completed_requests = sum(1 for req in self.data_requests.values() if req.status == DataRequestStatus.COMPLETED)
        pending_requests = len(self.pending_requests)
        total_disputes = len(self.disputes)
        open_disputes = sum(1 for dispute in self.disputes.values() if dispute.status == DisputeStatus.OPEN)
        
        # Calculate average reputation
        if self.oracle_reputations:
            avg_reputation = sum(rep.overall_score for rep in self.oracle_reputations.values()) / len(self.oracle_reputations)
        else:
            avg_reputation = 0
            
        return {
            'total_oracles': len(self.oracle_nodes),
            'active_oracles': active_oracles,
            'total_requests': total_requests,
            'completed_requests': completed_requests,
            'pending_requests': pending_requests,
            'success_rate': (completed_requests / total_requests * 100) if total_requests > 0 else 0,
            'total_disputes': total_disputes,
            'open_disputes': open_disputes,
            'average_oracle_reputation': float(avg_reputation),
            'total_staked': sum(self.oracle_stakes.values()),
            'min_stake_requirement': self.min_stake_amount
        }
        
    def cleanup_expired_requests(self) -> int:
        """Clean up expired requests"""
        expired_count = 0
        current_time = int(time.time())
        
        for request_id in list(self.pending_requests):
            request = self.data_requests.get(request_id)
            if request and request.is_expired:
                request.status = DataRequestStatus.FAILED
                self.pending_requests.discard(request_id)
                expired_count += 1
                
        return expired_count
        
    def add_request_callback(self, callback: Callable):
        """Add callback for new requests"""
        self.request_callbacks.append(callback)
        
    def add_response_callback(self, callback: Callable):
        """Add callback for new responses"""
        self.response_callbacks.append(callback)