"""Smart Contract Engine Module

This module provides the core infrastructure for executing smart contracts
in a blockchain environment, including:

- Virtual Machine (VM) for contract execution
- Smart Contract Engine for deployment and management
- Gas metering and execution context
- Contract registry and metadata management
"""

from .vm import (
    SmartContractVM,
    SmartContract,
    ExecutionContext,
    ExecutionResult,
    OpCode,
    VMException,
    OutOfGasException,
    StackUnderflowException,
    InvalidOpcodeException
)

from .engine import (
    SmartContractEngine,
    ContractRegistry,
    ContractMetadata,
    TransactionReceipt,
    get_engine,
    reset_engine
)

__all__ = [
    # VM classes
    'SmartContractVM',
    'SmartContract',
    'ExecutionContext',
    'ExecutionResult',
    'OpCode',
    'VMException',
    'OutOfGasException',
    'StackUnderflowException',
    'InvalidOpcodeException',
    
    # Engine classes
    'SmartContractEngine',
    'ContractRegistry',
    'ContractMetadata',
    'TransactionReceipt',
    'get_engine',
    'reset_engine'
]

__version__ = '1.0.0'
__author__ = 'Blockchain Financial System'