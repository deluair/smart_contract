from typing import Dict, List, Any, Optional, Tuple
import json
import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
import traceback

class OpCode(Enum):
    """Virtual Machine Operation Codes"""
    # Stack operations
    PUSH = "PUSH"
    POP = "POP"
    DUP = "DUP"
    SWAP = "SWAP"
    
    # Arithmetic operations
    ADD = "ADD"
    SUB = "SUB"
    MUL = "MUL"
    DIV = "DIV"
    MOD = "MOD"
    
    # Comparison operations
    EQ = "EQ"
    LT = "LT"
    GT = "GT"
    
    # Logical operations
    AND = "AND"
    OR = "OR"
    NOT = "NOT"
    
    # Control flow
    JUMP = "JUMP"
    JUMPI = "JUMPI"
    CALL = "CALL"
    RETURN = "RETURN"
    REVERT = "REVERT"
    
    # Storage operations
    SLOAD = "SLOAD"
    SSTORE = "SSTORE"
    
    # Environment operations
    ADDRESS = "ADDRESS"
    BALANCE = "BALANCE"
    CALLER = "CALLER"
    CALLVALUE = "CALLVALUE"
    TIMESTAMP = "TIMESTAMP"
    BLOCKNUMBER = "BLOCKNUMBER"
    
    # Financial operations
    TRANSFER = "TRANSFER"
    MINT = "MINT"
    BURN = "BURN"
    
    # Market operations
    CREATE_ORDER = "CREATE_ORDER"
    CANCEL_ORDER = "CANCEL_ORDER"
    EXECUTE_TRADE = "EXECUTE_TRADE"
    GET_PRICE = "GET_PRICE"
    
    # Stop execution
    STOP = "STOP"

@dataclass
class ExecutionContext:
    """Context for smart contract execution"""
    caller: str
    contract_address: str
    value: int = 0
    gas_limit: int = 1000000
    gas_used: int = 0
    block_number: int = 0
    timestamp: int = field(default_factory=lambda: int(time.time()))
    data: bytes = b''
    
class ExecutionResult:
    """Result of contract execution"""
    def __init__(self, success: bool, return_data: Any = None, 
                 gas_used: int = 0, error: str = None, logs: List[Dict] = None):
        self.success = success
        self.return_data = return_data
        self.gas_used = gas_used
        self.error = error
        self.logs = logs or []
        
class VMException(Exception):
    """Virtual Machine Exception"""
    pass

# Alias for backward compatibility
VMError = VMException

class OutOfGasException(VMException):
    """Out of gas exception"""
    pass

class StackUnderflowException(VMException):
    """Stack underflow exception"""
    pass

class InvalidOpcodeException(VMException):
    """Invalid opcode exception"""
    pass

class SmartContractVM:
    """Smart Contract Virtual Machine"""
    
    def __init__(self):
        self.stack: List[Any] = []
        self.memory: Dict[str, Any] = {}
        self.storage: Dict[str, Dict[str, Any]] = {}  # contract_address -> storage
        self.balances: Dict[str, int] = {}
        self.contracts: Dict[str, 'SmartContract'] = {}
        self.logs: List[Dict] = []
        
        # Gas costs for operations
        self.gas_costs = {
            OpCode.PUSH: 3,
            OpCode.POP: 2,
            OpCode.ADD: 3,
            OpCode.SUB: 3,
            OpCode.MUL: 5,
            OpCode.DIV: 5,
            OpCode.SLOAD: 200,
            OpCode.SSTORE: 5000,
            OpCode.CALL: 700,
            OpCode.TRANSFER: 9000,
            OpCode.CREATE_ORDER: 10000,
            OpCode.EXECUTE_TRADE: 15000,
        }
        
    def execute_contract(self, contract_address: str, function_name: str, 
                        args: List[Any], context: ExecutionContext) -> ExecutionResult:
        """Execute a smart contract function"""
        try:
            if contract_address not in self.contracts:
                return ExecutionResult(False, error="Contract not found")
                
            contract = self.contracts[contract_address]
            
            # Initialize contract storage if not exists
            if contract_address not in self.storage:
                self.storage[contract_address] = {}
                
            # Reset execution state
            self.stack = []
            self.memory = {}
            self.logs = []
            
            # Execute the function
            result = self._execute_function(contract, function_name, args, context)
            
            return ExecutionResult(
                success=True,
                return_data=result,
                gas_used=context.gas_used,
                logs=self.logs.copy()
            )
            
        except OutOfGasException:
            return ExecutionResult(False, error="Out of gas", gas_used=context.gas_limit)
        except Exception as e:
            return ExecutionResult(False, error=str(e), gas_used=context.gas_used)
            
    def _execute_function(self, contract: 'SmartContract', function_name: str, 
                         args: List[Any], context: ExecutionContext) -> Any:
        """Execute a specific contract function"""
        if not hasattr(contract, function_name):
            raise VMException(f"Function {function_name} not found")
            
        # Set up execution environment
        self._setup_environment(context)
        
        # Get the function
        func = getattr(contract, function_name)
        
        # Execute with gas metering
        return self._execute_with_gas_metering(func, args, context)
        
    def _setup_environment(self, context: ExecutionContext):
        """Setup execution environment"""
        self.memory['caller'] = context.caller
        self.memory['contract_address'] = context.contract_address
        self.memory['value'] = context.value
        self.memory['block_number'] = context.block_number
        self.memory['timestamp'] = context.timestamp
        
    def _execute_with_gas_metering(self, func, args: List[Any], context: ExecutionContext) -> Any:
        """Execute function with gas metering"""
        # Charge base gas for function call
        self._consume_gas(context, 21000)  # Base transaction cost
        
        # Execute the function
        return func(*args)
        
    def _consume_gas(self, context: ExecutionContext, amount: int):
        """Consume gas and check limits"""
        context.gas_used += amount
        if context.gas_used > context.gas_limit:
            raise OutOfGasException("Gas limit exceeded")
            
    def execute_opcode(self, opcode: OpCode, operands: List[Any], context: ExecutionContext) -> Any:
        """Execute a single opcode"""
        # Consume gas for operation
        gas_cost = self.gas_costs.get(opcode, 1)
        self._consume_gas(context, gas_cost)
        
        if opcode == OpCode.PUSH:
            self.stack.append(operands[0])
            
        elif opcode == OpCode.POP:
            if not self.stack:
                raise StackUnderflowException("Stack underflow")
            return self.stack.pop()
            
        elif opcode == OpCode.ADD:
            if len(self.stack) < 2:
                raise StackUnderflowException("Stack underflow")
            b = self.stack.pop()
            a = self.stack.pop()
            self.stack.append(a + b)
            
        elif opcode == OpCode.SUB:
            if len(self.stack) < 2:
                raise StackUnderflowException("Stack underflow")
            b = self.stack.pop()
            a = self.stack.pop()
            self.stack.append(a - b)
            
        elif opcode == OpCode.MUL:
            if len(self.stack) < 2:
                raise StackUnderflowException("Stack underflow")
            b = self.stack.pop()
            a = self.stack.pop()
            self.stack.append(a * b)
            
        elif opcode == OpCode.DIV:
            if len(self.stack) < 2:
                raise StackUnderflowException("Stack underflow")
            b = self.stack.pop()
            a = self.stack.pop()
            if b == 0:
                raise VMException("Division by zero")
            self.stack.append(a // b)
            
        elif opcode == OpCode.SLOAD:
            key = str(operands[0])
            contract_storage = self.storage.get(context.contract_address, {})
            value = contract_storage.get(key, 0)
            self.stack.append(value)
            
        elif opcode == OpCode.SSTORE:
            key = str(operands[0])
            value = operands[1]
            if context.contract_address not in self.storage:
                self.storage[context.contract_address] = {}
            self.storage[context.contract_address][key] = value
            
        elif opcode == OpCode.BALANCE:
            address = str(operands[0])
            balance = self.balances.get(address, 0)
            self.stack.append(balance)
            
        elif opcode == OpCode.TRANSFER:
            to_address = str(operands[0])
            amount = int(operands[1])
            from_address = context.caller
            
            if self.balances.get(from_address, 0) < amount:
                raise VMException("Insufficient balance")
                
            self.balances[from_address] = self.balances.get(from_address, 0) - amount
            self.balances[to_address] = self.balances.get(to_address, 0) + amount
            
            # Log the transfer
            self.logs.append({
                'event': 'Transfer',
                'from': from_address,
                'to': to_address,
                'amount': amount,
                'timestamp': context.timestamp
            })
            
        elif opcode == OpCode.TIMESTAMP:
            self.stack.append(context.timestamp)
            
        elif opcode == OpCode.BLOCKNUMBER:
            self.stack.append(context.block_number)
            
        elif opcode == OpCode.CALLER:
            self.stack.append(context.caller)
            
        elif opcode == OpCode.ADDRESS:
            self.stack.append(context.contract_address)
            
        elif opcode == OpCode.EQ:
            if len(self.stack) < 2:
                raise StackUnderflowException("Stack underflow")
            b = self.stack.pop()
            a = self.stack.pop()
            self.stack.append(1 if a == b else 0)
            
        elif opcode == OpCode.LT:
            if len(self.stack) < 2:
                raise StackUnderflowException("Stack underflow")
            b = self.stack.pop()
            a = self.stack.pop()
            self.stack.append(1 if a < b else 0)
            
        elif opcode == OpCode.GT:
            if len(self.stack) < 2:
                raise StackUnderflowException("Stack underflow")
            b = self.stack.pop()
            a = self.stack.pop()
            self.stack.append(1 if a > b else 0)
            
        else:
            raise InvalidOpcodeException(f"Invalid opcode: {opcode}")
            
    def deploy_contract(self, contract: 'SmartContract', deployer: str) -> str:
        """Deploy a smart contract"""
        contract_address = self._generate_contract_address(contract, deployer)
        self.contracts[contract_address] = contract
        self.storage[contract_address] = {}
        
        # Set contract address and VM reference
        contract.address = contract_address
        contract.vm = self
        
        # Set initial context
        contract.context = ExecutionContext(
            caller=deployer,
            contract_address=contract_address
        )
                
        return contract_address
        
    def _generate_contract_address(self, contract: 'SmartContract', deployer: str) -> str:
        """Generate a unique contract address"""
        contract_code = str(contract.__class__.__name__)
        timestamp = str(int(time.time()))
        data = f"{deployer}{contract_code}{timestamp}"
        return hashlib.sha256(data.encode()).hexdigest()[:40]
        
    def get_contract_storage(self, contract_address: str) -> Dict[str, Any]:
        """Get contract storage"""
        return self.storage.get(contract_address, {})
        
    def get_balance(self, address: str) -> int:
        """Get account balance"""
        return self.balances.get(address, 0)
        
    def set_balance(self, address: str, amount: int):
        """Set account balance"""
        self.balances[address] = amount
        
    def add_balance(self, address: str, amount: int):
        """Add to account balance"""
        self.balances[address] = self.balances.get(address, 0) + amount

class SmartContract:
    """Base class for smart contracts"""
    
    def __init__(self):
        self.vm = None  # Will be set by the VM
        self.address = None  # Will be set when deployed
        self.context = None  # Execution context
        
    def _emit_event(self, event_name: str, data: Dict[str, Any]):
        """Emit an event"""
        if self.vm:
            self.vm.logs.append({
                'event': event_name,
                'contract': self.address,
                'data': data,
                'timestamp': int(time.time())
            })
            
    def _get_storage(self, key: str) -> Any:
        """Get value from contract storage"""
        if self.vm and self.address:
            return self.vm.storage.get(self.address, {}).get(key, None)
        return None
        
    def _set_storage(self, key: str, value: Any):
        """Set value in contract storage"""
        if self.vm and self.address:
            if self.address not in self.vm.storage:
                self.vm.storage[self.address] = {}
            self.vm.storage[self.address][key] = value
            
    def _get_caller(self) -> str:
        """Get the caller address"""
        if self.context:
            return self.context.caller
        if self.vm:
            return self.vm.memory.get('caller', '')
        return ''
        
    def _get_balance(self, address: str) -> int:
        """Get balance of an address"""
        if self.vm:
            return self.vm.balances.get(address, 0)
        return 0
        
    def _transfer(self, to_address: str, amount: int) -> bool:
        """Transfer tokens"""
        if self.vm:
            from_address = self._get_caller()
            if self.vm.balances.get(from_address, 0) >= amount:
                self.vm.balances[from_address] = self.vm.balances.get(from_address, 0) - amount
                self.vm.balances[to_address] = self.vm.balances.get(to_address, 0) + amount
                
                self._emit_event('Transfer', {
                    'from': from_address,
                    'to': to_address,
                    'amount': amount
                })
                return True
        return False