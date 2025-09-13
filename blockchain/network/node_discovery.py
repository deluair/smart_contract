"""Node Discovery for Blockchain Network

This module implements peer discovery mechanisms to find and connect
to other nodes in the blockchain network.
"""

import time
import random
import socket
import threading
from typing import List, Set, Dict, Optional
from dataclasses import dataclass
import json
import logging

@dataclass
class DiscoveredNode:
    """Represents a discovered network node"""
    address: str
    port: int
    last_seen: float
    services: List[str] = None
    version: str = None
    height: int = 0
    reliability_score: float = 1.0
    
    def __post_init__(self):
        if self.services is None:
            self.services = []
    
    @property
    def full_address(self) -> str:
        """Get full address in host:port format"""
        return f"{self.address}:{self.port}"

class NodeDiscovery:
    """Handles discovery of blockchain network nodes"""
    
    def __init__(self, bootstrap_nodes: List[str] = None, discovery_port: int = 8334):
        self.bootstrap_nodes = bootstrap_nodes or []
        self.discovery_port = discovery_port
        self.discovered_nodes: Dict[str, DiscoveredNode] = {}
        self.known_addresses: Set[str] = set()
        self.lock = threading.RLock()
        self.logger = logging.getLogger(__name__)
        
        # Discovery configuration
        self.max_nodes = 1000
        self.discovery_interval = 300  # 5 minutes
        self.node_timeout = 3600  # 1 hour
        self.ping_timeout = 5  # 5 seconds
        
        # Add bootstrap nodes to known addresses
        for node in self.bootstrap_nodes:
            self.known_addresses.add(node)
    
    def discover_peers(self, max_peers: int = 10) -> List[str]:
        """Discover new peers to connect to
        
        Args:
            max_peers (int): Maximum number of peers to return
            
        Returns:
            List[str]: List of peer addresses to connect to
        """
        discovered_peers = []
        
        try:
            # Clean up old nodes first
            self._cleanup_old_nodes()
            
            # Try different discovery methods
            self._discover_from_bootstrap()
            self._discover_from_dns()
            self._discover_from_known_nodes()
            
            # Get best peers to connect to
            with self.lock:
                # Sort nodes by reliability score and last seen
                sorted_nodes = sorted(
                    self.discovered_nodes.values(),
                    key=lambda n: (-n.reliability_score, -n.last_seen)
                )
                
                # Return up to max_peers addresses
                for node in sorted_nodes[:max_peers]:
                    if self._is_node_reachable(node):
                        discovered_peers.append(node.full_address)
            
            self.logger.info(f"Discovered {len(discovered_peers)} peers")
            
        except Exception as e:
            self.logger.error(f"Error during peer discovery: {e}")
        
        return discovered_peers
    
    def _discover_from_bootstrap(self):
        """Discover peers from bootstrap nodes"""
        for bootstrap_node in self.bootstrap_nodes:
            try:
                # Parse address
                if ':' in bootstrap_node:
                    host, port = bootstrap_node.split(':')
                    port = int(port)
                else:
                    host = bootstrap_node
                    port = 8333  # Default port
                
                # Add to discovered nodes
                self._add_discovered_node(host, port)
                
                # Try to get peer list from bootstrap node
                peer_list = self._request_peer_list(host, port)
                for peer_addr in peer_list:
                    self._parse_and_add_peer(peer_addr)
                    
            except Exception as e:
                self.logger.warning(f"Failed to discover from bootstrap node {bootstrap_node}: {e}")
    
    def _discover_from_dns(self):
        """Discover peers using DNS seeds"""
        # Common DNS seeds for blockchain networks
        dns_seeds = [
            'seed.blockchain.local',
            'dnsseed.blockchain.local',
            'seed1.blockchain.local',
            'seed2.blockchain.local'
        ]
        
        for seed in dns_seeds:
            try:
                # Resolve DNS seed
                addresses = socket.getaddrinfo(seed, None)
                
                for addr_info in addresses:
                    if addr_info[0] == socket.AF_INET:  # IPv4
                        host = addr_info[4][0]
                        self._add_discovered_node(host, 8333)  # Default port
                        
            except Exception as e:
                self.logger.debug(f"DNS seed {seed} not available: {e}")
    
    def _discover_from_known_nodes(self):
        """Discover peers by asking known nodes for their peer lists"""
        with self.lock:
            known_nodes = list(self.discovered_nodes.values())
        
        # Randomly select some known nodes to query
        query_nodes = random.sample(known_nodes, min(5, len(known_nodes)))
        
        for node in query_nodes:
            try:
                peer_list = self._request_peer_list(node.address, node.port)
                for peer_addr in peer_list:
                    self._parse_and_add_peer(peer_addr)
                    
            except Exception as e:
                self.logger.debug(f"Failed to get peer list from {node.full_address}: {e}")
    
    def _request_peer_list(self, host: str, port: int) -> List[str]:
        """Request peer list from a specific node
        
        Args:
            host (str): Node hostname/IP
            port (int): Node port
            
        Returns:
            List[str]: List of peer addresses
        """
        try:
            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.ping_timeout)
            sock.connect((host, port))
            
            # Send peer list request
            request = {
                'type': 'peer_list_request',
                'version': '1.0.0',
                'timestamp': time.time()
            }
            
            message = json.dumps(request).encode() + b'\n'
            sock.send(message)
            
            # Receive response
            response_data = sock.recv(4096)
            sock.close()
            
            if response_data:
                response = json.loads(response_data.decode().strip())
                if response.get('type') == 'peer_list_response':
                    return response.get('data', {}).get('peers', [])
            
        except Exception as e:
            self.logger.debug(f"Failed to request peer list from {host}:{port}: {e}")
        
        return []
    
    def _parse_and_add_peer(self, peer_addr: str):
        """Parse and add a peer address
        
        Args:
            peer_addr (str): Peer address in various formats
        """
        try:
            # Handle different address formats
            if ':' in peer_addr:
                host, port = peer_addr.split(':')
                port = int(port)
            else:
                host = peer_addr
                port = 8333  # Default port
            
            self._add_discovered_node(host, port)
            
        except Exception as e:
            self.logger.debug(f"Failed to parse peer address {peer_addr}: {e}")
    
    def _add_discovered_node(self, host: str, port: int):
        """Add a discovered node to the list
        
        Args:
            host (str): Node hostname/IP
            port (int): Node port
        """
        full_address = f"{host}:{port}"
        
        with self.lock:
            if full_address not in self.discovered_nodes:
                # Create new discovered node
                node = DiscoveredNode(
                    address=host,
                    port=port,
                    last_seen=time.time()
                )
                
                self.discovered_nodes[full_address] = node
                self.known_addresses.add(full_address)
                
                self.logger.debug(f"Added discovered node: {full_address}")
            else:
                # Update last seen time
                self.discovered_nodes[full_address].last_seen = time.time()
    
    def _is_node_reachable(self, node: DiscoveredNode) -> bool:
        """Check if a node is reachable
        
        Args:
            node (DiscoveredNode): Node to check
            
        Returns:
            bool: True if node is reachable
        """
        try:
            # Try to connect to the node
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.ping_timeout)
            result = sock.connect_ex((node.address, node.port))
            sock.close()
            
            is_reachable = result == 0
            
            # Update reliability score
            if is_reachable:
                node.reliability_score = min(1.0, node.reliability_score + 0.1)
            else:
                node.reliability_score = max(0.0, node.reliability_score - 0.2)
            
            return is_reachable
            
        except Exception:
            node.reliability_score = max(0.0, node.reliability_score - 0.2)
            return False
    
    def _cleanup_old_nodes(self):
        """Remove old and unreliable nodes"""
        current_time = time.time()
        nodes_to_remove = []
        
        with self.lock:
            for address, node in self.discovered_nodes.items():
                # Remove nodes that haven't been seen for too long
                if current_time - node.last_seen > self.node_timeout:
                    nodes_to_remove.append(address)
                # Remove nodes with very low reliability
                elif node.reliability_score < 0.1:
                    nodes_to_remove.append(address)
            
            # Remove old nodes
            for address in nodes_to_remove:
                del self.discovered_nodes[address]
                self.known_addresses.discard(address)
            
            # Limit total number of nodes
            if len(self.discovered_nodes) > self.max_nodes:
                # Keep only the best nodes
                sorted_nodes = sorted(
                    self.discovered_nodes.items(),
                    key=lambda x: (-x[1].reliability_score, -x[1].last_seen)
                )
                
                # Remove excess nodes
                excess_nodes = sorted_nodes[self.max_nodes:]
                for address, _ in excess_nodes:
                    del self.discovered_nodes[address]
                    self.known_addresses.discard(address)
        
        if nodes_to_remove:
            self.logger.info(f"Cleaned up {len(nodes_to_remove)} old/unreliable nodes")
    
    def add_peer_manually(self, address: str, port: int):
        """Manually add a peer to the discovery list
        
        Args:
            address (str): Peer address
            port (int): Peer port
        """
        self._add_discovered_node(address, port)
        self.logger.info(f"Manually added peer: {address}:{port}")
    
    def remove_peer(self, address: str):
        """Remove a peer from the discovery list
        
        Args:
            address (str): Peer address in host:port format
        """
        with self.lock:
            if address in self.discovered_nodes:
                del self.discovered_nodes[address]
                self.known_addresses.discard(address)
                self.logger.info(f"Removed peer: {address}")
    
    def get_peer_count(self) -> int:
        """Get the number of discovered peers
        
        Returns:
            int: Number of discovered peers
        """
        with self.lock:
            return len(self.discovered_nodes)
    
    def get_peer_list(self) -> List[str]:
        """Get list of all discovered peer addresses
        
        Returns:
            List[str]: List of peer addresses
        """
        with self.lock:
            return list(self.discovered_nodes.keys())
    
    def get_best_peers(self, count: int = 10) -> List[str]:
        """Get the best discovered peers
        
        Args:
            count (int): Number of peers to return
            
        Returns:
            List[str]: List of best peer addresses
        """
        with self.lock:
            sorted_nodes = sorted(
                self.discovered_nodes.values(),
                key=lambda n: (-n.reliability_score, -n.last_seen)
            )
            
            return [node.full_address for node in sorted_nodes[:count]]
    
    def get_discovery_stats(self) -> Dict[str, any]:
        """Get discovery statistics
        
        Returns:
            Dict[str, any]: Discovery statistics
        """
        with self.lock:
            total_nodes = len(self.discovered_nodes)
            reliable_nodes = sum(1 for node in self.discovered_nodes.values() 
                               if node.reliability_score > 0.5)
            
            avg_reliability = 0
            if total_nodes > 0:
                avg_reliability = sum(node.reliability_score 
                                    for node in self.discovered_nodes.values()) / total_nodes
            
            return {
                'total_discovered_nodes': total_nodes,
                'reliable_nodes': reliable_nodes,
                'bootstrap_nodes': len(self.bootstrap_nodes),
                'average_reliability': avg_reliability,
                'discovery_port': self.discovery_port,
                'max_nodes': self.max_nodes
            }