#!/usr/bin/env python3
"""
Smart Contract Platform - Main Application Entry Point

This is the main entry point for the Smart Contract Platform.
It initializes all components and provides a unified interface to run the system.

Usage:
    python main.py [options]
    
Options:
    --api-only          Run only the API server
    --blockchain-only   Run only the blockchain node
    --oracle-only       Run only the oracle system
    --port PORT         API server port (default: 5000)
    --host HOST         API server host (default: 0.0.0.0)
    --debug             Enable debug mode
    --help              Show this help message

Examples:
    python main.py                    # Run full system
    python main.py --api-only         # Run only API server
    python main.py --port 8080        # Run on port 8080
    python main.py --debug            # Run with debug enabled
"""

import sys
import argparse
import threading
import time
import signal
from typing import Optional

# Import all system components
from blockchain import Blockchain, ProofOfStakeConsensus, create_blockchain_system
from smart_contracts import SmartContractEngine, create_contract_engine
from wallet import AccountManager, create_wallet_system
from oracles import OracleManager, PriceFeedManager, create_oracle_system
from api import start_api_server, get_api_instance, health_check

class SmartContractPlatform:
    """Main platform class that orchestrates all components"""
    
    def __init__(self):
        self.blockchain = None
        self.consensus = None
        self.contract_engine = None
        self.account_manager = None
        self.oracle_manager = None
        self.price_feed = None
        self.api_server = None
        self.running = False
        self.threads = []
    
    def initialize_blockchain(self):
        """Initialize blockchain and consensus system"""
        print("Initializing blockchain system...")
        
        # Create consensus mechanism
        self.consensus = ProofOfStakeConsensus()
        
        # Create blockchain with consensus
        self.blockchain = create_blockchain_system(consensus=self.consensus)
        
        # Add genesis validators
        genesis_validators = [
            ("0x1234567890123456789012345678901234567890", "04a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890123456789012345678901234567890"),
            ("0x2345678901234567890123456789012345678901", "04b2c3d4e5f6789012345678901234567890123456789012345678901234567890123456789012345678901234567890a1"),
            ("0x3456789012345678901234567890123456789012", "04c3d4e5f6789012345678901234567890123456789012345678901234567890123456789012345678901234567890a1b2")
        ]
        
        for address, public_key in genesis_validators:
            self.consensus.register_validator(address, public_key, 1000)  # 1000 tokens stake
        
        print(f"✓ Blockchain initialized with {len(self.blockchain.chain)} blocks")
        print(f"✓ Consensus system ready with {len(self.consensus.validators)} validators")
    
    def initialize_smart_contracts(self):
        """Initialize smart contract system"""
        print("Initializing smart contract engine...")
        
        self.contract_engine = create_contract_engine(blockchain=self.blockchain)
        
        print("✓ Smart contract engine initialized")
        print("✓ VM ready for contract execution")
    
    def initialize_wallet_system(self):
        """Initialize wallet and account management"""
        print("Initializing wallet system...")
        
        self.account_manager = create_wallet_system(secret_key="your_secret_key_here_change_in_production")
        
        print("✓ Wallet system initialized")
        print("✓ Account manager ready")
    
    def initialize_oracle_system(self):
        """Initialize oracle and price feed system"""
        print("Initializing oracle system...")
        
        # Create oracle system
        self.oracle_manager, self.price_feed = create_oracle_system()
        
        # Register some oracle nodes
        oracle_nodes = [
            ("0x4567890123456789012345678901234567890123", "04a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890123456789012345678901234567890"),
            ("0x5678901234567890123456789012345678901234", "04b2c3d4e5f6789012345678901234567890123456789012345678901234567890123456789012345678901234567890a1"),
            ("0x6789012345678901234567890123456789012345", "04c3d4e5f6789012345678901234567890123456789012345678901234567890123456789012345678901234567890a1b2")
        ]
        
        # Import OracleType for supported_types
        from oracles.oracle_manager import OracleType
        
        for address, public_key in oracle_nodes:
            self.oracle_manager.register_oracle(
                oracle_address=address,
                public_key=public_key,
                stake_amount=10000,
                supported_types=[OracleType.PRICE_FEED]
            )
        
        print(f"✓ Oracle system initialized with {len(self.oracle_manager.oracle_nodes)} nodes")
        print("✓ Price feed system ready")
    
    def start_background_services(self):
        """Start background services"""
        print("Starting background services...")
        
        # Start price feed updates
        if self.price_feed:
            price_thread = threading.Thread(
                target=self._price_feed_worker,
                daemon=True
            )
            price_thread.start()
            self.threads.append(price_thread)
            print("✓ Price feed service started")
        
        # Start consensus mechanism
        if self.consensus:
            consensus_thread = threading.Thread(
                target=self._consensus_worker,
                daemon=True
            )
            consensus_thread.start()
            self.threads.append(consensus_thread)
            print("✓ Consensus service started")
    
    def _price_feed_worker(self):
        """Background worker for price feed updates"""
        symbols = ['BTC', 'ETH', 'USDC', 'DAI']
        
        while self.running:
            try:
                for symbol in symbols:
                    # Update price feeds
                    self.price_feed.update_price(symbol)
                
                # Sleep for 30 seconds between updates
                time.sleep(30)
            except Exception as e:
                print(f"Price feed error: {e}")
                time.sleep(60)  # Wait longer on error
    
    def _consensus_worker(self):
        """Background worker for consensus mechanism"""
        while self.running:
            try:
                # Process pending transactions and create blocks
                if hasattr(self.blockchain, 'pending_transactions') and self.blockchain.pending_transactions:
                    # Select validator and create block
                    validator = self.consensus.select_validator()
                    if validator:
                        # In a real implementation, this would create and validate blocks
                        pass
                
                # Sleep for block time (e.g., 12 seconds)
                time.sleep(12)
            except Exception as e:
                print(f"Consensus error: {e}")
                time.sleep(30)
    
    def start_api_server(self, host='0.0.0.0', port=5000, debug=False):
        """Start the API server"""
        print(f"Starting API server on {host}:{port}...")
        
        # Initialize API with all components
        api = get_api_instance()
        api.blockchain = self.blockchain
        api.consensus = self.consensus
        api.contract_engine = self.contract_engine
        api.account_manager = self.account_manager
        api.oracle_manager = self.oracle_manager
        api.price_feed = self.price_feed
        
        # Start API server in a separate thread
        api_thread = threading.Thread(
            target=lambda: start_api_server(host, port, debug),
            daemon=True
        )
        api_thread.start()
        self.threads.append(api_thread)
        
        print(f"✓ API server started at http://{host}:{port}")
        print(f"✓ Web interface available at http://{host}:{port}/web")
    
    def start_full_system(self, host='0.0.0.0', port=5000, debug=False):
        """Start the complete system"""
        print("="*60)
        print("Smart Contract Platform - Starting Full System")
        print("="*60)
        
        self.running = True
        
        try:
            # Initialize all components
            self.initialize_blockchain()
            self.initialize_smart_contracts()
            self.initialize_wallet_system()
            self.initialize_oracle_system()
            
            # Start background services
            self.start_background_services()
            
            # Start API server
            self.start_api_server(host, port, debug)
            
            print("\n" + "="*60)
            print("🚀 Smart Contract Platform is now running!")
            print("="*60)
            print(f"📊 Dashboard: http://{host}:{port}/web")
            print(f"🔗 API Docs: http://{host}:{port}/api/docs")
            print(f"⛓️  Blockchain: {len(self.blockchain.chain)} blocks")
            print(f"🏛️  Validators: {len(self.consensus.validators)}")
            print(f"🔮 Oracles: {len(self.oracle_manager.oracles)}")
            print("\nPress Ctrl+C to stop the system")
            print("="*60)
            
            # Keep main thread alive
            try:
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                self.stop_system()
                
        except Exception as e:
            print(f"❌ Failed to start system: {e}")
            self.stop_system()
            sys.exit(1)
    
    def start_component(self, component, **kwargs):
        """Start a specific component only"""
        print(f"Starting {component} component...")
        
        self.running = True
        
        if component == 'api':
            self.initialize_blockchain()
            self.initialize_smart_contracts()
            self.initialize_wallet_system()
            self.initialize_oracle_system()
            self.start_api_server(**kwargs)
            
        elif component == 'blockchain':
            self.initialize_blockchain()
            self.start_background_services()
            
        elif component == 'oracle':
            self.initialize_oracle_system()
            self.start_background_services()
        
        print(f"✓ {component.title()} component started")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop_system()
    
    def stop_system(self):
        """Stop the system gracefully"""
        print("\n🛑 Stopping Smart Contract Platform...")
        
        self.running = False
        
        # Wait for threads to finish
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=5)
        
        print("✓ System stopped successfully")
    
    def get_system_status(self):
        """Get current system status"""
        return {
            'running': self.running,
            'blockchain': self.blockchain is not None,
            'consensus': self.consensus is not None,
            'contracts': self.contract_engine is not None,
            'wallet': self.account_manager is not None,
            'oracles': self.oracle_manager is not None,
            'price_feed': self.price_feed is not None,
            'threads': len(self.threads),
            'health': health_check()
        }

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Smart Contract Platform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument('--api-only', action='store_true',
                       help='Run only the API server')
    parser.add_argument('--blockchain-only', action='store_true',
                       help='Run only the blockchain node')
    parser.add_argument('--oracle-only', action='store_true',
                       help='Run only the oracle system')
    parser.add_argument('--port', type=int, default=5000,
                       help='API server port (default: 5000)')
    parser.add_argument('--host', default='0.0.0.0',
                       help='API server host (default: 0.0.0.0)')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug mode')
    
    args = parser.parse_args()
    
    # Create platform instance
    platform = SmartContractPlatform()
    
    # Setup signal handlers for graceful shutdown
    def signal_handler(signum, frame):
        platform.stop_system()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Determine what to run
        if args.api_only:
            platform.start_component('api', host=args.host, port=args.port, debug=args.debug)
        elif args.blockchain_only:
            platform.start_component('blockchain')
        elif args.oracle_only:
            platform.start_component('oracle')
        else:
            # Run full system
            platform.start_full_system(host=args.host, port=args.port, debug=args.debug)
            
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()