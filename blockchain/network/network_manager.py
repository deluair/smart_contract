"""Network Manager for Blockchain P2P Communication

This module implements the main network manager that coordinates
all networking activities for the blockchain platform.
"""

import asyncio
import socket
import threading
import time
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
import json
import logging

from .peer_manager import PeerManager
from .message_handler import MessageHandler
from .node_discovery import NodeDiscovery
from .protocol import NetworkProtocol, MessageType

@dataclass
class NetworkConfig:
    """Network configuration"""
    port: int = 8333
    host: str = '0.0.0.0'
    max_peers: int = 50
    connection_timeout: int = 30
    heartbeat_interval: int = 60
    bootstrap_nodes: List[str] = None
    
    def __post_init__(self):
        if self.bootstrap_nodes is None:
            self.bootstrap_nodes = []

class NetworkManager:
    """Main network manager for blockchain P2P communication"""
    
    def __init__(self, port=8333, max_peers=50, bootstrap_nodes=None):
        self.config = NetworkConfig(
            port=port,
            max_peers=max_peers,
            bootstrap_nodes=bootstrap_nodes or []
        )
        
        # Core components
        self.peer_manager = PeerManager(max_peers=max_peers)
        self.message_handler = MessageHandler()
        self.node_discovery = NodeDiscovery(bootstrap_nodes=self.config.bootstrap_nodes)
        self.protocol = NetworkProtocol()
        
        # Network state
        self.running = False
        self.server_socket = None
        self.threads = []
        
        # Event callbacks
        self.on_peer_connected = None
        self.on_peer_disconnected = None
        self.on_message_received = None
        self.on_block_received = None
        self.on_transaction_received = None
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
    def start(self):
        """Start the network manager"""
        if self.running:
            return
            
        self.logger.info(f"Starting network manager on port {self.config.port}")
        self.running = True
        
        try:
            # Start server socket
            self._start_server()
            
            # Start background services
            self._start_background_services()
            
            # Connect to bootstrap nodes
            self._connect_to_bootstrap_nodes()
            
            self.logger.info("Network manager started successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to start network manager: {e}")
            self.stop()
            raise
    
    def stop(self):
        """Stop the network manager"""
        if not self.running:
            return
            
        self.logger.info("Stopping network manager")
        self.running = False
        
        # Close server socket
        if self.server_socket:
            self.server_socket.close()
            
        # Disconnect all peers
        self.peer_manager.disconnect_all()
        
        # Wait for threads to finish
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=5)
                
        self.logger.info("Network manager stopped")
    
    def _start_server(self):
        """Start the server socket to accept incoming connections"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.config.host, self.config.port))
        self.server_socket.listen(10)
        
        # Start accepting connections in a separate thread
        accept_thread = threading.Thread(target=self._accept_connections, daemon=True)
        accept_thread.start()
        self.threads.append(accept_thread)
        
    def _accept_connections(self):
        """Accept incoming peer connections"""
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                
                if self.peer_manager.can_accept_peer():
                    # Handle new peer connection
                    peer_thread = threading.Thread(
                        target=self._handle_peer_connection,
                        args=(client_socket, address),
                        daemon=True
                    )
                    peer_thread.start()
                    self.threads.append(peer_thread)
                else:
                    # Too many peers, reject connection
                    client_socket.close()
                    
            except Exception as e:
                if self.running:
                    self.logger.error(f"Error accepting connection: {e}")
                    
    def _handle_peer_connection(self, client_socket, address):
        """Handle communication with a connected peer"""
        peer_id = f"{address[0]}:{address[1]}"
        
        try:
            # Add peer to manager
            peer = self.peer_manager.add_peer(peer_id, client_socket, address)
            
            if self.on_peer_connected:
                self.on_peer_connected(peer)
                
            # Handle messages from this peer
            while self.running and peer.is_connected:
                try:
                    # Receive message
                    message = self.protocol.receive_message(client_socket)
                    if message:
                        self._process_message(peer, message)
                    else:
                        break
                        
                except Exception as e:
                    self.logger.error(f"Error handling peer {peer_id}: {e}")
                    break
                    
        except Exception as e:
            self.logger.error(f"Error with peer connection {peer_id}: {e}")
        finally:
            # Clean up peer connection
            self.peer_manager.remove_peer(peer_id)
            client_socket.close()
            
            if self.on_peer_disconnected:
                self.on_peer_disconnected(peer_id)
    
    def _process_message(self, peer, message):
        """Process a received message"""
        try:
            # Handle message based on type
            if message['type'] == MessageType.HANDSHAKE.value:
                self._handle_handshake(peer, message)
            elif message['type'] == MessageType.BLOCK.value:
                self._handle_block_message(peer, message)
            elif message['type'] == MessageType.TRANSACTION.value:
                self._handle_transaction_message(peer, message)
            elif message['type'] == MessageType.PING.value:
                self._handle_ping(peer, message)
            elif message['type'] == MessageType.PONG.value:
                self._handle_pong(peer, message)
            else:
                self.logger.warning(f"Unknown message type: {message['type']}")
                
            # Call general message callback
            if self.on_message_received:
                self.on_message_received(peer, message)
                
        except Exception as e:
            self.logger.error(f"Error processing message: {e}")
    
    def _handle_handshake(self, peer, message):
        """Handle handshake message"""
        # Update peer info
        peer.version = message.get('version', '1.0.0')
        peer.services = message.get('services', [])
        peer.height = message.get('height', 0)
        
        # Send handshake response
        response = self.protocol.create_handshake_message(
            version='1.0.0',
            services=['full_node'],
            height=0  # Should be actual blockchain height
        )
        self.send_message(peer.peer_id, response)
    
    def _handle_block_message(self, peer, message):
        """Handle block message"""
        if self.on_block_received:
            self.on_block_received(peer, message['data'])
    
    def _handle_transaction_message(self, peer, message):
        """Handle transaction message"""
        if self.on_transaction_received:
            self.on_transaction_received(peer, message['data'])
    
    def _handle_ping(self, peer, message):
        """Handle ping message"""
        # Send pong response
        pong = self.protocol.create_pong_message(message.get('nonce', 0))
        self.send_message(peer.peer_id, pong)
    
    def _handle_pong(self, peer, message):
        """Handle pong message"""
        # Update peer's last seen time
        peer.last_seen = time.time()
    
    def _start_background_services(self):
        """Start background network services"""
        # Start heartbeat service
        heartbeat_thread = threading.Thread(target=self._heartbeat_worker, daemon=True)
        heartbeat_thread.start()
        self.threads.append(heartbeat_thread)
        
        # Start node discovery service
        discovery_thread = threading.Thread(target=self._discovery_worker, daemon=True)
        discovery_thread.start()
        self.threads.append(discovery_thread)
    
    def _heartbeat_worker(self):
        """Send periodic heartbeat messages to peers"""
        while self.running:
            try:
                # Send ping to all connected peers
                for peer in self.peer_manager.get_connected_peers():
                    ping = self.protocol.create_ping_message()
                    self.send_message(peer.peer_id, ping)
                
                # Remove stale peers
                self.peer_manager.remove_stale_peers(timeout=300)  # 5 minutes
                
                time.sleep(self.config.heartbeat_interval)
                
            except Exception as e:
                self.logger.error(f"Heartbeat error: {e}")
                time.sleep(60)
    
    def _discovery_worker(self):
        """Discover and connect to new peers"""
        while self.running:
            try:
                # Discover new peers
                discovered_peers = self.node_discovery.discover_peers()
                
                # Connect to new peers if we have capacity
                for peer_address in discovered_peers:
                    if self.peer_manager.can_accept_peer():
                        self.connect_to_peer(peer_address)
                
                time.sleep(300)  # Run every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Discovery error: {e}")
                time.sleep(600)  # Wait longer on error
    
    def _connect_to_bootstrap_nodes(self):
        """Connect to bootstrap nodes"""
        for node_address in self.config.bootstrap_nodes:
            try:
                self.connect_to_peer(node_address)
            except Exception as e:
                self.logger.warning(f"Failed to connect to bootstrap node {node_address}: {e}")
    
    def connect_to_peer(self, address):
        """Connect to a specific peer
        
        Args:
            address (str): Peer address in format 'host:port'
        """
        if not self.peer_manager.can_accept_peer():
            return False
            
        try:
            host, port = address.split(':')
            port = int(port)
            
            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.connection_timeout)
            sock.connect((host, port))
            
            # Add peer and start handling
            peer = self.peer_manager.add_peer(address, sock, (host, port))
            
            # Send handshake
            handshake = self.protocol.create_handshake_message(
                version='1.0.0',
                services=['full_node'],
                height=0
            )
            self.send_message(address, handshake)
            
            # Start handling this peer in a separate thread
            peer_thread = threading.Thread(
                target=self._handle_peer_connection,
                args=(sock, (host, port)),
                daemon=True
            )
            peer_thread.start()
            self.threads.append(peer_thread)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to peer {address}: {e}")
            return False
    
    def send_message(self, peer_id, message):
        """Send a message to a specific peer
        
        Args:
            peer_id (str): Peer identifier
            message (dict): Message to send
        """
        peer = self.peer_manager.get_peer(peer_id)
        if peer and peer.is_connected:
            try:
                self.protocol.send_message(peer.socket, message)
                return True
            except Exception as e:
                self.logger.error(f"Failed to send message to {peer_id}: {e}")
                self.peer_manager.remove_peer(peer_id)
                return False
        return False
    
    def broadcast_message(self, message, exclude_peers=None):
        """Broadcast a message to all connected peers
        
        Args:
            message (dict): Message to broadcast
            exclude_peers (list): List of peer IDs to exclude
        """
        exclude_peers = exclude_peers or []
        sent_count = 0
        
        for peer in self.peer_manager.get_connected_peers():
            if peer.peer_id not in exclude_peers:
                if self.send_message(peer.peer_id, message):
                    sent_count += 1
        
        return sent_count
    
    def get_network_info(self):
        """Get current network information
        
        Returns:
            dict: Network status and statistics
        """
        return {
            'running': self.running,
            'port': self.config.port,
            'connected_peers': len(self.peer_manager.get_connected_peers()),
            'max_peers': self.config.max_peers,
            'bootstrap_nodes': self.config.bootstrap_nodes,
            'peer_list': [peer.peer_id for peer in self.peer_manager.get_connected_peers()]
        }
    
    def get_peer_info(self, peer_id):
        """Get information about a specific peer
        
        Args:
            peer_id (str): Peer identifier
            
        Returns:
            dict: Peer information or None if not found
        """
        peer = self.peer_manager.get_peer(peer_id)
        if peer:
            return {
                'peer_id': peer.peer_id,
                'address': peer.address,
                'connected_at': peer.connected_at,
                'last_seen': peer.last_seen,
                'version': peer.version,
                'services': peer.services,
                'height': peer.height,
                'is_connected': peer.is_connected
            }
        return None