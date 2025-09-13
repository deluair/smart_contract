from typing import Dict, List, Optional, Set, Tuple
import time
import random
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from decimal import Decimal, getcontext

from ..core.block import Block
from ..core.transaction import Transaction
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from security.signatures import SignatureValidator
from security.cryptography import CryptoUtils

# Set precision for staking calculations
getcontext().prec = 28

class ValidatorStatus(Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    SLASHED = "SLASHED"
    EXITING = "EXITING"
    EXITED = "EXITED"

class SlashingReason(Enum):
    DOUBLE_SIGNING = "DOUBLE_SIGNING"
    INACTIVITY = "INACTIVITY"
    INVALID_BLOCK = "INVALID_BLOCK"
    MALICIOUS_BEHAVIOR = "MALICIOUS_BEHAVIOR"

@dataclass
class Validator:
    """Proof of Stake Validator"""
    address: str
    public_key: str
    stake: int  # Amount staked
    delegated_stake: int  # Stake delegated by others
    status: ValidatorStatus
    activation_epoch: int
    exit_epoch: int = 0
    slashed: bool = False
    slashing_reason: Optional[SlashingReason] = None
    
    # Performance metrics
    blocks_proposed: int = 0
    blocks_validated: int = 0
    missed_blocks: int = 0
    last_active_epoch: int = 0
    
    # Rewards and penalties
    accumulated_rewards: int = 0
    accumulated_penalties: int = 0
    
    # Commission for delegators
    commission_rate: int = 1000  # 10% in basis points
    
    @property
    def total_stake(self) -> int:
        """Total stake including delegated stake"""
        return self.stake + self.delegated_stake
    
    @property
    def is_active(self) -> bool:
        """Check if validator is active"""
        return self.status == ValidatorStatus.ACTIVE and not self.slashed

@dataclass
class Delegation:
    """Stake delegation to a validator"""
    delegator: str
    validator: str
    amount: int
    delegation_epoch: int
    undelegation_epoch: int = 0
    rewards_claimed: int = 0

@dataclass
class EpochData:
    """Data for a consensus epoch"""
    epoch: int
    start_time: int
    end_time: int
    total_stake: int
    active_validators: int
    blocks_produced: int
    average_block_time: float
    finalized_blocks: List[str] = field(default_factory=list)

@dataclass
class SlashingEvent:
    """Record of a slashing event"""
    validator: str
    reason: SlashingReason
    epoch: int
    evidence: Dict[str, any]
    penalty_amount: int
    timestamp: int

class ProofOfStake:
    """Proof of Stake Consensus Mechanism"""
    
    def __init__(self, min_stake: int = 32 * 10**18, epoch_duration: int = 3600):
        # Core parameters
        self.min_stake = min_stake  # Minimum stake to become validator
        self.epoch_duration = epoch_duration  # Epoch duration in seconds
        self.max_validators = 1000  # Maximum number of validators
        
        # Validator management
        self.validators: Dict[str, Validator] = {}
        self.delegations: Dict[str, List[Delegation]] = {}  # delegator -> delegations
        self.validator_delegations: Dict[str, List[Delegation]] = {}  # validator -> delegations
        
        # Consensus state
        self.current_epoch = 0
        self.epoch_data: Dict[int, EpochData] = {}
        self.validator_queue: List[str] = []  # Queue for validator selection
        self.finalized_checkpoints: Dict[int, str] = {}  # epoch -> block_hash
        
        # Slashing and penalties
        self.slashing_events: List[SlashingEvent] = []
        self.double_sign_evidence: Dict[str, List[Dict]] = {}  # validator -> evidence
        
        # Rewards and economics
        self.base_reward_per_epoch = 1000 * 10**18  # Base reward per epoch
        self.inactivity_penalty_rate = 100  # Penalty rate for inactivity (basis points)
        self.slashing_penalty_rate = 5000  # 50% penalty for slashing
        
        # Block production
        self.block_proposers: Dict[int, str] = {}  # slot -> validator
        self.attestations: Dict[str, Set[str]] = {}  # block_hash -> validator_addresses
        
        # Randomness for validator selection
        self.randomness_seed = hashlib.sha256(b"genesis_seed").hexdigest()
        
        # Signature validator
        self.signature_validator = SignatureValidator()
        
    def register_validator(self, address: str, public_key: str, stake: int, 
                          commission_rate: int = 1000) -> bool:
        """Register a new validator"""
        if stake < self.min_stake:
            return False
            
        if address in self.validators:
            return False  # Validator already exists
            
        if len(self.validators) >= self.max_validators:
            return False  # Too many validators
            
        # Create validator
        validator = Validator(
            address=address,
            public_key=public_key,
            stake=stake,
            delegated_stake=0,
            status=ValidatorStatus.INACTIVE,  # Starts inactive
            activation_epoch=self.current_epoch + 1,  # Activate next epoch
            commission_rate=commission_rate
        )
        
        self.validators[address] = validator
        
        return True
        
    def activate_validator(self, address: str) -> bool:
        """Activate a validator for consensus participation"""
        if address not in self.validators:
            return False
            
        validator = self.validators[address]
        
        if validator.total_stake < self.min_stake:
            return False
            
        if validator.status != ValidatorStatus.INACTIVE:
            return False
            
        validator.status = ValidatorStatus.ACTIVE
        validator.activation_epoch = self.current_epoch
        
        # Add to validator queue
        if address not in self.validator_queue:
            self.validator_queue.append(address)
            
        return True
        
    def delegate_stake(self, delegator: str, validator: str, amount: int) -> bool:
        """Delegate stake to a validator"""
        if validator not in self.validators:
            return False
            
        if amount <= 0:
            return False
            
        # Create delegation
        delegation = Delegation(
            delegator=delegator,
            validator=validator,
            amount=amount,
            delegation_epoch=self.current_epoch
        )
        
        # Update delegations
        if delegator not in self.delegations:
            self.delegations[delegator] = []
        self.delegations[delegator].append(delegation)
        
        if validator not in self.validator_delegations:
            self.validator_delegations[validator] = []
        self.validator_delegations[validator].append(delegation)
        
        # Update validator's delegated stake
        self.validators[validator].delegated_stake += amount
        
        return True
        
    def undelegate_stake(self, delegator: str, validator: str, amount: int) -> bool:
        """Undelegate stake from a validator"""
        if delegator not in self.delegations:
            return False
            
        # Find delegation
        delegations = self.delegations[delegator]
        total_delegated = sum(d.amount for d in delegations if d.validator == validator and d.undelegation_epoch == 0)
        
        if total_delegated < amount:
            return False  # Insufficient delegated amount
            
        # Mark delegations for undelegation
        remaining_amount = amount
        for delegation in delegations:
            if delegation.validator == validator and delegation.undelegation_epoch == 0:
                if remaining_amount <= 0:
                    break
                    
                undelegate_amount = min(delegation.amount, remaining_amount)
                delegation.undelegation_epoch = self.current_epoch
                remaining_amount -= undelegate_amount
                
                # Update validator's delegated stake
                self.validators[validator].delegated_stake -= undelegate_amount
                
        return True
        
    def select_block_proposer(self, slot: int) -> Optional[str]:
        """Select block proposer for a given slot using weighted random selection"""
        active_validators = [addr for addr, val in self.validators.items() if val.is_active]
        
        if not active_validators:
            return None
            
        # Calculate weights based on stake
        weights = []
        for addr in active_validators:
            validator = self.validators[addr]
            weights.append(validator.total_stake)
            
        # Use deterministic randomness based on slot and epoch
        seed = f"{self.randomness_seed}_{self.current_epoch}_{slot}"
        random.seed(int(CryptoUtils.hash_sha256_hex(seed.encode()), 16) % (2**32))
        
        # Weighted random selection
        total_weight = sum(weights)
        if total_weight == 0:
            return None
            
        rand_val = random.randint(0, total_weight - 1)
        cumulative_weight = 0
        
        for i, weight in enumerate(weights):
            cumulative_weight += weight
            if rand_val < cumulative_weight:
                selected = active_validators[i]
                self.block_proposers[slot] = selected
                return selected
                
        return active_validators[-1]  # Fallback
        
    def validate_block_proposal(self, block: Block, proposer: str) -> bool:
        """Validate a block proposal"""
        if proposer not in self.validators:
            return False
            
        validator = self.validators[proposer]
        if not validator.is_active:
            return False
            
        # Check if proposer is scheduled for this slot
        expected_proposer = self.block_proposers.get(block.header.timestamp, None)
        if expected_proposer and expected_proposer != proposer:
            return False
            
        # Validate block structure and transactions
        if not self._validate_block_structure(block):
            return False
            
        # Check for double signing
        if self._check_double_signing(proposer, block):
            self._slash_validator(proposer, SlashingReason.DOUBLE_SIGNING, {
                'block_hash': block.hash,
                'timestamp': block.header.timestamp
            })
            return False
            
        return True
        
    def attest_block(self, block_hash: str, validator: str) -> bool:
        """Validator attests to a block"""
        if validator not in self.validators:
            return False
            
        if not self.validators[validator].is_active:
            return False
            
        # Add attestation
        if block_hash not in self.attestations:
            self.attestations[block_hash] = set()
            
        self.attestations[block_hash].add(validator)
        
        # Update validator metrics
        self.validators[validator].blocks_validated += 1
        self.validators[validator].last_active_epoch = self.current_epoch
        
        return True
        
    def finalize_block(self, block_hash: str) -> bool:
        """Finalize a block if it has enough attestations"""
        if block_hash not in self.attestations:
            return False
            
        attestations = self.attestations[block_hash]
        total_stake = sum(self.validators[addr].total_stake for addr in attestations if addr in self.validators)
        
        # Calculate total active stake
        total_active_stake = sum(val.total_stake for val in self.validators.values() if val.is_active)
        
        # Require 2/3 majority of stake for finalization
        if total_stake * 3 >= total_active_stake * 2:
            self.finalized_checkpoints[self.current_epoch] = block_hash
            
            # Add to epoch data
            if self.current_epoch in self.epoch_data:
                self.epoch_data[self.current_epoch].finalized_blocks.append(block_hash)
                
            return True
            
        return False
        
    def advance_epoch(self) -> bool:
        """Advance to the next epoch"""
        # Finalize current epoch
        self._finalize_epoch()
        
        # Advance epoch
        self.current_epoch += 1
        
        # Initialize new epoch
        self._initialize_epoch()
        
        # Process validator queue (activate/deactivate validators)
        self._process_validator_queue()
        
        # Distribute rewards
        self._distribute_epoch_rewards()
        
        # Check for inactivity and slash inactive validators
        self._check_inactivity()
        
        # Update randomness seed
        self._update_randomness_seed()
        
        return True
        
    def _finalize_epoch(self):
        """Finalize the current epoch"""
        current_time = int(time.time())
        
        # Create epoch data
        active_validators = len([v for v in self.validators.values() if v.is_active])
        total_stake = sum(v.total_stake for v in self.validators.values() if v.is_active)
        
        epoch_data = EpochData(
            epoch=self.current_epoch,
            start_time=current_time - self.epoch_duration,
            end_time=current_time,
            total_stake=total_stake,
            active_validators=active_validators,
            blocks_produced=len([p for p in self.block_proposers.values()]),
            average_block_time=self.epoch_duration / max(1, len(self.block_proposers))
        )
        
        self.epoch_data[self.current_epoch] = epoch_data
        
    def _initialize_epoch(self):
        """Initialize a new epoch"""
        # Clear block proposers for new epoch
        self.block_proposers.clear()
        
        # Clear attestations
        self.attestations.clear()
        
    def _process_validator_queue(self):
        """Process validator activation/deactivation queue"""
        # Activate pending validators
        for addr in list(self.validator_queue):
            if addr in self.validators:
                validator = self.validators[addr]
                if (validator.status == ValidatorStatus.INACTIVE and 
                    validator.total_stake >= self.min_stake):
                    validator.status = ValidatorStatus.ACTIVE
                    validator.activation_epoch = self.current_epoch
                    
        # Process exit requests
        for validator in self.validators.values():
            if (validator.status == ValidatorStatus.EXITING and 
                self.current_epoch >= validator.exit_epoch):
                validator.status = ValidatorStatus.EXITED
                
    def _distribute_epoch_rewards(self):
        """Distribute rewards to validators and delegators"""
        active_validators = [v for v in self.validators.values() if v.is_active]
        
        if not active_validators:
            return
            
        # Calculate total rewards for the epoch
        total_active_stake = sum(v.total_stake for v in active_validators)
        
        for validator in active_validators:
            # Calculate validator's share of rewards
            stake_ratio = validator.total_stake / total_active_stake if total_active_stake > 0 else 0
            validator_reward = int(self.base_reward_per_epoch * stake_ratio)
            
            # Apply performance multiplier
            performance_multiplier = self._calculate_performance_multiplier(validator)
            validator_reward = int(validator_reward * performance_multiplier)
            
            # Calculate commission for validator
            commission = (validator_reward * validator.commission_rate) // 10000
            delegator_reward = validator_reward - commission
            
            # Distribute to validator
            validator.accumulated_rewards += commission
            
            # Distribute to delegators
            if validator.address in self.validator_delegations:
                delegations = self.validator_delegations[validator.address]
                active_delegations = [d for d in delegations if d.undelegation_epoch == 0]
                
                total_delegated = sum(d.amount for d in active_delegations)
                
                for delegation in active_delegations:
                    if total_delegated > 0:
                        delegation_ratio = delegation.amount / total_delegated
                        delegation_reward = int(delegator_reward * delegation_ratio)
                        delegation.rewards_claimed += delegation_reward
                        
    def _calculate_performance_multiplier(self, validator: Validator) -> float:
        """Calculate performance multiplier for rewards"""
        # Base multiplier
        multiplier = 1.0
        
        # Penalty for missed blocks
        if validator.blocks_proposed > 0:
            miss_rate = validator.missed_blocks / validator.blocks_proposed
            multiplier *= max(0.5, 1.0 - miss_rate)
            
        # Bonus for consistent participation
        if validator.last_active_epoch == self.current_epoch:
            multiplier *= 1.1
            
        return multiplier
        
    def _check_inactivity(self):
        """Check for inactive validators and apply penalties"""
        for validator in self.validators.values():
            if not validator.is_active:
                continue
                
            # Check if validator has been inactive
            epochs_inactive = self.current_epoch - validator.last_active_epoch
            
            if epochs_inactive > 5:  # Inactive for 5 epochs
                # Apply inactivity penalty
                penalty = (validator.total_stake * self.inactivity_penalty_rate) // 10000
                validator.accumulated_penalties += penalty
                
                # Slash if inactive for too long
                if epochs_inactive > 20:  # 20 epochs
                    self._slash_validator(validator.address, SlashingReason.INACTIVITY, {
                        'epochs_inactive': epochs_inactive,
                        'last_active_epoch': validator.last_active_epoch
                    })
                    
    def _slash_validator(self, validator_addr: str, reason: SlashingReason, evidence: Dict[str, any]):
        """Slash a validator for malicious behavior"""
        if validator_addr not in self.validators:
            return
            
        validator = self.validators[validator_addr]
        
        # Calculate slashing penalty
        penalty_amount = (validator.total_stake * self.slashing_penalty_rate) // 10000
        
        # Apply slashing
        validator.slashed = True
        validator.slashing_reason = reason
        validator.status = ValidatorStatus.SLASHED
        validator.accumulated_penalties += penalty_amount
        
        # Record slashing event
        slashing_event = SlashingEvent(
            validator=validator_addr,
            reason=reason,
            epoch=self.current_epoch,
            evidence=evidence,
            penalty_amount=penalty_amount,
            timestamp=int(time.time())
        )
        
        self.slashing_events.append(slashing_event)
        
        # Remove from active validator set
        if validator_addr in self.validator_queue:
            self.validator_queue.remove(validator_addr)
            
    def _check_double_signing(self, validator: str, block: Block) -> bool:
        """Check if validator is double signing"""
        # In a real implementation, this would check for conflicting blocks
        # at the same height/slot signed by the same validator
        
        if validator not in self.double_sign_evidence:
            self.double_sign_evidence[validator] = []
            
        # Store block evidence
        evidence = {
            'block_hash': block.hash,
            'timestamp': block.header.timestamp,
            'height': block.header.height
        }
        
        # Check for conflicting blocks
        for existing_evidence in self.double_sign_evidence[validator]:
            if (existing_evidence['timestamp'] == evidence['timestamp'] and
                existing_evidence['block_hash'] != evidence['block_hash']):
                return True  # Double signing detected
                
        self.double_sign_evidence[validator].append(evidence)
        
        # Keep only recent evidence (last 100 blocks)
        if len(self.double_sign_evidence[validator]) > 100:
            self.double_sign_evidence[validator] = self.double_sign_evidence[validator][-100:]
            
        return False
        
    def _validate_block_structure(self, block: Block) -> bool:
        """Validate block structure and transactions"""
        # Basic block validation
        if not block.hash or not block.header:
            return False
            
        # Validate transactions
        for tx in block.transactions:
            if not self._validate_transaction(tx):
                return False
                
        return True
        
    def _validate_transaction(self, transaction: Transaction) -> bool:
        """Validate a transaction"""
        # Basic transaction validation
        if not transaction.hash or not transaction.signature:
            return False
            
        # Verify signature
        return self.signature_validator.verify_transaction_signature(transaction)
        
    def _update_randomness_seed(self):
        """Update randomness seed for next epoch"""
        # Combine current seed with epoch data
        epoch_hash = hashlib.sha256(f"{self.current_epoch}_{int(time.time())}".encode()).hexdigest()
        self.randomness_seed = hashlib.sha256(f"{self.randomness_seed}_{epoch_hash}".encode()).hexdigest()
        
    def get_validator_info(self, address: str) -> Optional[Dict[str, any]]:
        """Get comprehensive validator information"""
        if address not in self.validators:
            return None
            
        validator = self.validators[address]
        
        # Calculate delegator info
        delegations = self.validator_delegations.get(address, [])
        active_delegations = [d for d in delegations if d.undelegation_epoch == 0]
        
        return {
            'address': validator.address,
            'public_key': validator.public_key,
            'stake': validator.stake,
            'delegated_stake': validator.delegated_stake,
            'total_stake': validator.total_stake,
            'status': validator.status.value,
            'activation_epoch': validator.activation_epoch,
            'exit_epoch': validator.exit_epoch,
            'slashed': validator.slashed,
            'slashing_reason': validator.slashing_reason.value if validator.slashing_reason else None,
            'blocks_proposed': validator.blocks_proposed,
            'blocks_validated': validator.blocks_validated,
            'missed_blocks': validator.missed_blocks,
            'last_active_epoch': validator.last_active_epoch,
            'accumulated_rewards': validator.accumulated_rewards,
            'accumulated_penalties': validator.accumulated_penalties,
            'commission_rate': validator.commission_rate,
            'delegator_count': len(active_delegations),
            'is_active': validator.is_active
        }
        
    def get_consensus_stats(self) -> Dict[str, any]:
        """Get consensus mechanism statistics"""
        active_validators = [v for v in self.validators.values() if v.is_active]
        total_validators = len(self.validators)
        total_stake = sum(v.total_stake for v in active_validators)
        
        return {
            'current_epoch': self.current_epoch,
            'total_validators': total_validators,
            'active_validators': len(active_validators),
            'total_stake': total_stake,
            'min_stake': self.min_stake,
            'epoch_duration': self.epoch_duration,
            'finalized_checkpoints': len(self.finalized_checkpoints),
            'slashing_events': len(self.slashing_events),
            'base_reward_per_epoch': self.base_reward_per_epoch,
            'validator_queue_length': len(self.validator_queue)
        }
        
    def get_epoch_info(self, epoch: int) -> Optional[Dict[str, any]]:
        """Get information about a specific epoch"""
        if epoch not in self.epoch_data:
            return None
            
        epoch_data = self.epoch_data[epoch]
        
        return {
            'epoch': epoch_data.epoch,
            'start_time': epoch_data.start_time,
            'end_time': epoch_data.end_time,
            'total_stake': epoch_data.total_stake,
            'active_validators': epoch_data.active_validators,
            'blocks_produced': epoch_data.blocks_produced,
            'average_block_time': epoch_data.average_block_time,
            'finalized_blocks': epoch_data.finalized_blocks,
            'is_finalized': epoch in self.finalized_checkpoints
        }

# Alias for backward compatibility
ProofOfStakeConsensus = ProofOfStake