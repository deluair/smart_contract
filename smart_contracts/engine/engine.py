from typing import Dict, List, Any, Optional, Tuple, Type
import json
import hashlib
import time
from dataclasses import dataclass, field
import threading
import logging
from concurrent.futures import ThreadPoolExecutor, Future

from .vm import SmartContractVM, SmartContract, ExecutionContext, ExecutionResult

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ContractMetadata:
    """Metadata for deployed contracts"""
    address: str
    name: str
    version: str
    deployer: str
    deployment_time: int
    source_code_hash: str
    abi: Dict[str, Any]
    gas_limit: int = 1000000
    is_active: bool = True

@dataclass
class TransactionReceipt:
    """Receipt for contract transactions"""
    transaction_hash: str
    contract_address: str
    function_name: str
    caller: str
    gas_used: int
    success: bool
    return_data: Any
    logs: List[Dict]
    timestamp: int
    error: Optional[str] = None

class ContractRegistry:
    """Registry for managing deployed contracts"""
    
    def __init__(self):
        self.contracts: Dict[str, ContractMetadata] = {}
        self.contract_instances: Dict[str, SmartContract] = {}
        self.lock = threading.RLock()
        
    def register_contract(self, metadata: ContractMetadata, instance: SmartContract):
        """Register a new contract"""
        with self.lock:
            self.contracts[metadata.address] = metadata
            self.contract_instances[metadata.address] = instance
            logger.info(f"Contract {metadata.name} registered at {metadata.address}")
            
    def get_contract(self, address: str) -> Optional[SmartContract]:
        """Get contract instance by address"""
        return self.contract_instances.get(address)
        
    def get_metadata(self, address: str) -> Optional[ContractMetadata]:
        """Get contract metadata by address"""
        return self.contracts.get(address)
        
    def list_contracts(self) -> List[ContractMetadata]:
        """List all registered contracts"""
        return list(self.contracts.values())
        
    def deactivate_contract(self, address: str) -> bool:
        """Deactivate a contract"""
        with self.lock:
            if address in self.contracts:
                self.contracts[address].is_active = False
                logger.info(f"Contract {address} deactivated")
                return True
            return False

class SmartContractEngine:
    """Main engine for smart contract execution and management"""
    
    def __init__(self, max_workers: int = 10):
        self.vm = SmartContractVM()
        self.registry = ContractRegistry()
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.transaction_history: List[TransactionReceipt] = []
        self.pending_transactions: Dict[str, Future] = {}
        self.lock = threading.RLock()
        
        # Engine configuration
        self.default_gas_limit = 1000000
        self.max_gas_limit = 10000000
        self.base_gas_price = 1000000000  # 1 Gwei
        
    def deploy_contract(self, contract_class: Type[SmartContract], 
                       deployer: str, constructor_args: List[Any] = None,
                       gas_limit: int = None) -> Tuple[str, TransactionReceipt]:
        """Deploy a smart contract"""
        try:
            # Create contract instance
            if constructor_args:
                contract_instance = contract_class(*constructor_args)
            else:
                contract_instance = contract_class()
                
            # Generate contract address
            contract_address = self._generate_contract_address(contract_class, deployer)
            
            # Set up contract
            contract_instance.vm = self.vm
            contract_instance.address = contract_address
            
            # Deploy to VM
            self.vm.contracts[contract_address] = contract_instance
            self.vm.storage[contract_address] = {}
            
            # Create metadata
            metadata = ContractMetadata(
                address=contract_address,
                name=contract_class.__name__,
                version="1.0.0",
                deployer=deployer,
                deployment_time=int(time.time()),
                source_code_hash=self._hash_contract_code(contract_class),
                abi=self._generate_abi(contract_class),
                gas_limit=gas_limit or self.default_gas_limit
            )
            
            # Register contract
            self.registry.register_contract(metadata, contract_instance)
            
            # Create deployment receipt
            receipt = TransactionReceipt(
                transaction_hash=self._generate_transaction_hash(deployer, contract_address),
                contract_address=contract_address,
                function_name="constructor",
                caller=deployer,
                gas_used=50000,  # Deployment gas cost
                success=True,
                return_data=contract_address,
                logs=[],
                timestamp=int(time.time())
            )
            
            self.transaction_history.append(receipt)
            
            logger.info(f"Contract {contract_class.__name__} deployed at {contract_address}")
            return contract_address, receipt
            
        except Exception as e:
            logger.error(f"Contract deployment failed: {e}")
            raise
            
    def call_contract(self, contract_address: str, function_name: str, 
                     args: List[Any], caller: str, value: int = 0,
                     gas_limit: int = None) -> TransactionReceipt:
        """Call a contract function"""
        try:
            # Validate contract
            contract = self.registry.get_contract(contract_address)
            if not contract:
                raise ValueError(f"Contract not found: {contract_address}")
                
            metadata = self.registry.get_metadata(contract_address)
            if not metadata.is_active:
                raise ValueError(f"Contract is inactive: {contract_address}")
                
            # Create execution context
            context = ExecutionContext(
                caller=caller,
                contract_address=contract_address,
                value=value,
                gas_limit=gas_limit or metadata.gas_limit,
                block_number=self._get_current_block_number(),
                timestamp=int(time.time())
            )
            
            # Execute contract function
            result = self.vm.execute_contract(contract_address, function_name, args, context)
            
            # Create transaction receipt
            receipt = TransactionReceipt(
                transaction_hash=self._generate_transaction_hash(caller, contract_address, function_name),
                contract_address=contract_address,
                function_name=function_name,
                caller=caller,
                gas_used=result.gas_used,
                success=result.success,
                return_data=result.return_data,
                logs=result.logs,
                timestamp=context.timestamp,
                error=result.error
            )
            
            self.transaction_history.append(receipt)
            
            if result.success:
                logger.info(f"Contract call successful: {contract_address}.{function_name}")
            else:
                logger.error(f"Contract call failed: {result.error}")
                
            return receipt
            
        except Exception as e:
            logger.error(f"Contract call error: {e}")
            # Create error receipt
            receipt = TransactionReceipt(
                transaction_hash=self._generate_transaction_hash(caller, contract_address, function_name),
                contract_address=contract_address,
                function_name=function_name,
                caller=caller,
                gas_used=0,
                success=False,
                return_data=None,
                logs=[],
                timestamp=int(time.time()),
                error=str(e)
            )
            self.transaction_history.append(receipt)
            return receipt
            
    def call_contract_async(self, contract_address: str, function_name: str,
                           args: List[Any], caller: str, value: int = 0,
                           gas_limit: int = None) -> str:
        """Call contract function asynchronously"""
        transaction_hash = self._generate_transaction_hash(caller, contract_address, function_name)
        
        future = self.executor.submit(
            self.call_contract, contract_address, function_name, 
            args, caller, value, gas_limit
        )
        
        self.pending_transactions[transaction_hash] = future
        return transaction_hash
        
    def get_transaction_result(self, transaction_hash: str) -> Optional[TransactionReceipt]:
        """Get result of async transaction"""
        if transaction_hash in self.pending_transactions:
            future = self.pending_transactions[transaction_hash]
            if future.done():
                result = future.result()
                del self.pending_transactions[transaction_hash]
                return result
            return None  # Still pending
            
        # Check transaction history
        for receipt in self.transaction_history:
            if receipt.transaction_hash == transaction_hash:
                return receipt
                
        return None
        
    def get_contract_state(self, contract_address: str) -> Dict[str, Any]:
        """Get contract storage state"""
        return self.vm.get_contract_storage(contract_address)
        
    def get_account_balance(self, address: str) -> int:
        """Get account balance"""
        return self.vm.get_balance(address)
        
    def set_account_balance(self, address: str, amount: int):
        """Set account balance (for testing)"""
        self.vm.set_balance(address, amount)
        
    def get_transaction_history(self, address: str = None, 
                               contract_address: str = None) -> List[TransactionReceipt]:
        """Get transaction history with optional filtering"""
        history = self.transaction_history
        
        if address:
            history = [tx for tx in history if tx.caller == address]
            
        if contract_address:
            history = [tx for tx in history if tx.contract_address == contract_address]
            
        return history
        
    def estimate_gas(self, contract_address: str, function_name: str,
                    args: List[Any], caller: str) -> int:
        """Estimate gas cost for a transaction"""
        # Simple estimation - in production, this would be more sophisticated
        base_cost = 21000  # Base transaction cost
        
        # Add costs based on function complexity
        if function_name in ['transfer', 'approve']:
            return base_cost + 5000
        elif function_name in ['mint', 'burn']:
            return base_cost + 10000
        elif 'trade' in function_name.lower():
            return base_cost + 50000
        else:
            return base_cost + 25000
            
    def _generate_contract_address(self, contract_class: Type[SmartContract], deployer: str) -> str:
        """Generate unique contract address"""
        data = f"{deployer}{contract_class.__name__}{int(time.time())}{len(self.registry.contracts)}"
        return hashlib.sha256(data.encode()).hexdigest()[:40]
        
    def _generate_transaction_hash(self, caller: str, contract_address: str, 
                                  function_name: str = "") -> str:
        """Generate unique transaction hash"""
        data = f"{caller}{contract_address}{function_name}{int(time.time() * 1000000)}"
        return hashlib.sha256(data.encode()).hexdigest()
        
    def _hash_contract_code(self, contract_class: Type[SmartContract]) -> str:
        """Hash contract source code"""
        import inspect
        source = inspect.getsource(contract_class)
        return hashlib.sha256(source.encode()).hexdigest()
        
    def _generate_abi(self, contract_class: Type[SmartContract]) -> Dict[str, Any]:
        """Generate ABI for contract"""
        import inspect
        
        abi = {
            "name": contract_class.__name__,
            "functions": [],
            "events": []
        }
        
        # Get public methods
        for name, method in inspect.getmembers(contract_class, predicate=inspect.isfunction):
            if not name.startswith('_'):
                sig = inspect.signature(method)
                abi["functions"].append({
                    "name": name,
                    "inputs": [{
                        "name": param_name,
                        "type": str(param.annotation) if param.annotation != param.empty else "any"
                    } for param_name, param in sig.parameters.items() if param_name != 'self'],
                    "outputs": [{
                        "type": str(sig.return_annotation) if sig.return_annotation != sig.empty else "any"
                    }]
                })
                
        return abi
        
    def _get_current_block_number(self) -> int:
        """Get current block number (mock implementation)"""
        return int(time.time()) // 15  # New block every 15 seconds
        
    def shutdown(self):
        """Shutdown the engine"""
        self.executor.shutdown(wait=True)
        logger.info("Smart contract engine shutdown complete")
        
    def get_engine_stats(self) -> Dict[str, Any]:
        """Get engine statistics"""
        return {
            "total_contracts": len(self.registry.contracts),
            "active_contracts": len([c for c in self.registry.contracts.values() if c.is_active]),
            "total_transactions": len(self.transaction_history),
            "pending_transactions": len(self.pending_transactions),
            "successful_transactions": len([tx for tx in self.transaction_history if tx.success]),
            "failed_transactions": len([tx for tx in self.transaction_history if not tx.success])
        }

# Global engine instance
_engine_instance = None
_engine_lock = threading.Lock()

def get_engine() -> SmartContractEngine:
    """Get global engine instance (singleton)"""
    global _engine_instance
    if _engine_instance is None:
        with _engine_lock:
            if _engine_instance is None:
                _engine_instance = SmartContractEngine()
    return _engine_instance

def reset_engine():
    """Reset global engine instance (for testing)"""
    global _engine_instance
    with _engine_lock:
        if _engine_instance:
            _engine_instance.shutdown()
        _engine_instance = None