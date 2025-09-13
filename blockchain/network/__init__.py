"""Blockchain Network Module

This module provides networking functionality for the blockchain platform,
including peer-to-peer communication, node discovery, and network protocols.

Features:
- P2P networking
- Node discovery
- Message broadcasting
- Network synchronization
- Peer management

Components:
- NetworkManager: Main networking coordinator
- PeerManager: Peer connection management
- MessageHandler: Network message processing
- NodeDiscovery: Automatic peer discovery
- NetworkProtocol: Protocol definitions
"""

from .network_manager import NetworkManager
from .peer_manager import PeerManager
from .message_handler import MessageHandler
from .node_discovery import NodeDiscovery
from .protocol import NetworkProtocol, MessageType

__all__ = [
    'NetworkManager',
    'PeerManager', 
    'MessageHandler',
    'NodeDiscovery',
    'NetworkProtocol',
    'MessageType',
    'create_network_system'
]

__version__ = '1.0.0'

def create_network_system(port=8333, max_peers=50, bootstrap_nodes=None):
    """Create and configure the network system
    
    Args:
        port (int): Port to listen on
        max_peers (int): Maximum number of peer connections
        bootstrap_nodes (list): List of bootstrap node addresses
    
    Returns:
        NetworkManager: Configured network manager
    """
    network_manager = NetworkManager(
        port=port,
        max_peers=max_peers,
        bootstrap_nodes=bootstrap_nodes or []
    )
    
    return network_manager

print(f"Blockchain Network module loaded - Version {__version__}")