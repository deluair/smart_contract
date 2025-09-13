"""Peer Manager for Blockchain Network

This module manages peer connections, including connection lifecycle,
peer information, and connection limits.
"""

import time
import threading
from typing import Dict, List, Optional
from dataclasses import dataclass
import socket

@dataclass
class Peer:
    """Represents a network peer"""
    peer_id: str
    socket: socket.socket
    address: tuple
    connected_at: float
    last_seen: float
    version: str = None
    services: List[str] = None
    height: int = 0
    is_connected: bool = True
    
    def __post_init__(self):
        if self.services is None:
            self.services = []

class PeerManager:
    """Manages peer connections for the blockchain network"""
    
    def __init__(self, max_peers=50):
        self.max_peers = max_peers
        self.peers: Dict[str, Peer] = {}
        self.lock = threading.RLock()
        
    def add_peer(self, peer_id: str, socket: socket.socket, address: tuple) -> Optional[Peer]:
        """Add a new peer connection
        
        Args:
            peer_id (str): Unique identifier for the peer
            socket (socket.socket): Socket connection to the peer
            address (tuple): Peer's network address (host, port)
            
        Returns:
            Peer: The created peer object, or None if couldn't add
        """
        with self.lock:
            # Check if we can accept more peers
            if len(self.peers) >= self.max_peers:
                return None
                
            # Check if peer already exists
            if peer_id in self.peers:
                return self.peers[peer_id]
            
            # Create new peer
            current_time = time.time()
            peer = Peer(
                peer_id=peer_id,
                socket=socket,
                address=address,
                connected_at=current_time,
                last_seen=current_time
            )
            
            self.peers[peer_id] = peer
            return peer
    
    def remove_peer(self, peer_id: str) -> bool:
        """Remove a peer connection
        
        Args:
            peer_id (str): Peer identifier to remove
            
        Returns:
            bool: True if peer was removed, False if not found
        """
        with self.lock:
            if peer_id in self.peers:
                peer = self.peers[peer_id]
                
                # Close socket if still connected
                try:
                    if peer.socket:
                        peer.socket.close()
                except:
                    pass
                
                # Mark as disconnected and remove
                peer.is_connected = False
                del self.peers[peer_id]
                return True
            return False
    
    def get_peer(self, peer_id: str) -> Optional[Peer]:
        """Get a peer by ID
        
        Args:
            peer_id (str): Peer identifier
            
        Returns:
            Peer: The peer object or None if not found
        """
        with self.lock:
            return self.peers.get(peer_id)
    
    def get_connected_peers(self) -> List[Peer]:
        """Get all connected peers
        
        Returns:
            List[Peer]: List of connected peer objects
        """
        with self.lock:
            return [peer for peer in self.peers.values() if peer.is_connected]
    
    def get_all_peers(self) -> List[Peer]:
        """Get all peers (connected and disconnected)
        
        Returns:
            List[Peer]: List of all peer objects
        """
        with self.lock:
            return list(self.peers.values())
    
    def can_accept_peer(self) -> bool:
        """Check if we can accept a new peer connection
        
        Returns:
            bool: True if we can accept more peers
        """
        with self.lock:
            return len(self.peers) < self.max_peers
    
    def disconnect_peer(self, peer_id: str) -> bool:
        """Disconnect a specific peer
        
        Args:
            peer_id (str): Peer identifier to disconnect
            
        Returns:
            bool: True if peer was disconnected, False if not found
        """
        with self.lock:
            peer = self.peers.get(peer_id)
            if peer and peer.is_connected:
                try:
                    peer.socket.close()
                except:
                    pass
                peer.is_connected = False
                return True
            return False
    
    def disconnect_all(self):
        """Disconnect all peers"""
        with self.lock:
            for peer in self.peers.values():
                if peer.is_connected:
                    try:
                        peer.socket.close()
                    except:
                        pass
                    peer.is_connected = False
    
    def update_peer_activity(self, peer_id: str):
        """Update the last seen time for a peer
        
        Args:
            peer_id (str): Peer identifier
        """
        with self.lock:
            peer = self.peers.get(peer_id)
            if peer:
                peer.last_seen = time.time()
    
    def remove_stale_peers(self, timeout: int = 300):
        """Remove peers that haven't been seen for a while
        
        Args:
            timeout (int): Timeout in seconds (default: 5 minutes)
        """
        current_time = time.time()
        stale_peers = []
        
        with self.lock:
            for peer_id, peer in self.peers.items():
                if current_time - peer.last_seen > timeout:
                    stale_peers.append(peer_id)
        
        # Remove stale peers
        for peer_id in stale_peers:
            self.remove_peer(peer_id)
    
    def get_peer_count(self) -> int:
        """Get the number of connected peers
        
        Returns:
            int: Number of connected peers
        """
        with self.lock:
            return len([peer for peer in self.peers.values() if peer.is_connected])
    
    def get_peer_addresses(self) -> List[str]:
        """Get addresses of all connected peers
        
        Returns:
            List[str]: List of peer addresses in 'host:port' format
        """
        with self.lock:
            addresses = []
            for peer in self.peers.values():
                if peer.is_connected:
                    host, port = peer.address
                    addresses.append(f"{host}:{port}")
            return addresses
    
    def find_peers_by_service(self, service: str) -> List[Peer]:
        """Find peers that support a specific service
        
        Args:
            service (str): Service name to search for
            
        Returns:
            List[Peer]: List of peers supporting the service
        """
        with self.lock:
            matching_peers = []
            for peer in self.peers.values():
                if peer.is_connected and peer.services and service in peer.services:
                    matching_peers.append(peer)
            return matching_peers
    
    def get_best_peers(self, count: int = 5) -> List[Peer]:
        """Get the best peers based on various criteria
        
        Args:
            count (int): Number of peers to return
            
        Returns:
            List[Peer]: List of best peers
        """
        with self.lock:
            connected_peers = self.get_connected_peers()
            
            # Sort by criteria: height (descending), connection time (ascending)
            sorted_peers = sorted(
                connected_peers,
                key=lambda p: (-p.height, p.connected_at)
            )
            
            return sorted_peers[:count]
    
    def get_random_peers(self, count: int = 3) -> List[Peer]:
        """Get random connected peers
        
        Args:
            count (int): Number of random peers to return
            
        Returns:
            List[Peer]: List of random peers
        """
        import random
        
        with self.lock:
            connected_peers = self.get_connected_peers()
            
            if len(connected_peers) <= count:
                return connected_peers
            
            return random.sample(connected_peers, count)
    
    def get_peer_statistics(self) -> dict:
        """Get statistics about peer connections
        
        Returns:
            dict: Peer statistics
        """
        with self.lock:
            connected_peers = self.get_connected_peers()
            
            if not connected_peers:
                return {
                    'total_peers': 0,
                    'connected_peers': 0,
                    'average_height': 0,
                    'services': {},
                    'versions': {}
                }
            
            # Calculate statistics
            total_height = sum(peer.height for peer in connected_peers)
            average_height = total_height / len(connected_peers) if connected_peers else 0
            
            # Count services
            services = {}
            for peer in connected_peers:
                if peer.services:
                    for service in peer.services:
                        services[service] = services.get(service, 0) + 1
            
            # Count versions
            versions = {}
            for peer in connected_peers:
                if peer.version:
                    versions[peer.version] = versions.get(peer.version, 0) + 1
            
            return {
                'total_peers': len(self.peers),
                'connected_peers': len(connected_peers),
                'max_peers': self.max_peers,
                'average_height': average_height,
                'services': services,
                'versions': versions
            }
    
    def is_peer_connected(self, peer_id: str) -> bool:
        """Check if a peer is currently connected
        
        Args:
            peer_id (str): Peer identifier
            
        Returns:
            bool: True if peer is connected
        """
        with self.lock:
            peer = self.peers.get(peer_id)
            return peer is not None and peer.is_connected
    
    def update_peer_info(self, peer_id: str, version: str = None, 
                        services: List[str] = None, height: int = None):
        """Update peer information
        
        Args:
            peer_id (str): Peer identifier
            version (str): Peer's software version
            services (List[str]): Services supported by peer
            height (int): Peer's blockchain height
        """
        with self.lock:
            peer = self.peers.get(peer_id)
            if peer:
                if version is not None:
                    peer.version = version
                if services is not None:
                    peer.services = services
                if height is not None:
                    peer.height = height
                
                # Update last seen time
                peer.last_seen = time.time()