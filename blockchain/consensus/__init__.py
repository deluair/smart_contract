"""Blockchain Consensus Module

This module implements various consensus mechanisms for the blockchain system.
Currently supports:

- Proof of Stake (PoS) consensus with validator management
- Staking and delegation functionality
- Slashing conditions for malicious behavior
- Epoch-based finality and rewards distribution

The consensus module ensures network security and decentralization
through economic incentives and penalties.
"""

from .pos import (
    ProofOfStake,
    Validator,
    Delegation,
    EpochData,
    SlashingEvent,
    ValidatorStatus,
    SlashingReason
)

__all__ = [
    'ProofOfStake',
    'Validator',
    'Delegation',
    'EpochData',
    'SlashingEvent',
    'ValidatorStatus',
    'SlashingReason'
]

__version__ = '1.0.0'
__author__ = 'Blockchain Financial System'

# Consensus constants
DEFAULT_MIN_STAKE = 32 * 10**18  # 32 tokens minimum stake
DEFAULT_EPOCH_DURATION = 3600  # 1 hour epochs
DEFAULT_MAX_VALIDATORS = 1000  # Maximum active validators

# Economic parameters
BASE_REWARD_PER_EPOCH = 1000 * 10**18  # Base reward per epoch
INACTIVITY_PENALTY_RATE = 100  # 1% penalty for inactivity
SLASHING_PENALTY_RATE = 5000  # 50% penalty for slashing

# Finality parameters
FINALITY_THRESHOLD = 6667  # 2/3 majority required (66.67%)
INACTIVITY_THRESHOLD = 5  # Epochs before inactivity penalty
SLASHING_THRESHOLD = 20  # Epochs before slashing for inactivity

def create_pos_consensus(min_stake: int = DEFAULT_MIN_STAKE, 
                        epoch_duration: int = DEFAULT_EPOCH_DURATION) -> ProofOfStake:
    """Create a Proof of Stake consensus instance with default parameters"""
    return ProofOfStake(min_stake=min_stake, epoch_duration=epoch_duration)

def get_consensus_info():
    """Get information about available consensus mechanisms"""
    return {
        'mechanisms': ['ProofOfStake'],
        'default': 'ProofOfStake',
        'parameters': {
            'min_stake': DEFAULT_MIN_STAKE,
            'epoch_duration': DEFAULT_EPOCH_DURATION,
            'max_validators': DEFAULT_MAX_VALIDATORS,
            'base_reward': BASE_REWARD_PER_EPOCH,
            'inactivity_penalty': INACTIVITY_PENALTY_RATE,
            'slashing_penalty': SLASHING_PENALTY_RATE
        }
    }