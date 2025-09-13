"""Message Handler for Blockchain Network

This module handles processing of network messages between peers,
including validation, routing, and response generation.
"""

import time
import json
import hashlib
from typing import Dict, Any, Optional, Callable
from dataclasses import dataclass
import logging

from .protocol import MessageType

@dataclass
class MessageStats:
    """Statistics for message handling"""
    messages_received: int = 0
    messages_sent: int = 0
    messages_processed: int = 0
    messages_failed: int = 0
    bytes_received: int = 0
    bytes_sent: int = 0
    last_activity: float = 0

class MessageHandler:
    """Handles network message processing and routing"""
    
    def __init__(self):
        self.stats = MessageStats()
        self.message_handlers: Dict[str, Callable] = {}
        self.message_cache: Dict[str, float] = {}  # Message ID -> timestamp
        self.cache_timeout = 300  # 5 minutes
        self.logger = logging.getLogger(__name__)
        
        # Register default handlers
        self._register_default_handlers()
    
    def _register_default_handlers(self):
        """Register default message handlers"""
        self.register_handler(MessageType.HANDSHAKE.value, self._handle_handshake)
        self.register_handler(MessageType.PING.value, self._handle_ping)
        self.register_handler(MessageType.PONG.value, self._handle_pong)
        self.register_handler(MessageType.BLOCK.value, self._handle_block)
        self.register_handler(MessageType.TRANSACTION.value, self._handle_transaction)
        self.register_handler(MessageType.BLOCK_REQUEST.value, self._handle_block_request)
        self.register_handler(MessageType.PEER_LIST.value, self._handle_peer_list)
    
    def register_handler(self, message_type: str, handler: Callable):
        """Register a message handler for a specific message type
        
        Args:
            message_type (str): Type of message to handle
            handler (Callable): Function to handle the message
        """
        self.message_handlers[message_type] = handler
        self.logger.debug(f"Registered handler for message type: {message_type}")
    
    def process_message(self, peer, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process an incoming message
        
        Args:
            peer: The peer that sent the message
            message (Dict[str, Any]): The message to process
            
        Returns:
            Optional[Dict[str, Any]]: Response message if any
        """
        try:
            # Update statistics
            self.stats.messages_received += 1
            self.stats.last_activity = time.time()
            
            # Validate message structure
            if not self._validate_message(message):
                self.stats.messages_failed += 1
                self.logger.warning(f"Invalid message structure from {peer.peer_id}")
                return None
            
            # Check for duplicate messages
            message_id = self._get_message_id(message)
            if self._is_duplicate_message(message_id):
                self.logger.debug(f"Duplicate message {message_id} from {peer.peer_id}")
                return None
            
            # Cache message ID
            self._cache_message_id(message_id)
            
            # Get message type
            message_type = message.get('type')
            
            # Find and execute handler
            handler = self.message_handlers.get(message_type)
            if handler:
                response = handler(peer, message)
                self.stats.messages_processed += 1
                return response
            else:
                self.logger.warning(f"No handler for message type: {message_type}")
                self.stats.messages_failed += 1
                return None
                
        except Exception as e:
            self.logger.error(f"Error processing message: {e}")
            self.stats.messages_failed += 1
            return None
    
    def _validate_message(self, message: Dict[str, Any]) -> bool:
        """Validate message structure
        
        Args:
            message (Dict[str, Any]): Message to validate
            
        Returns:
            bool: True if message is valid
        """
        required_fields = ['type', 'timestamp', 'version']
        
        for field in required_fields:
            if field not in message:
                return False
        
        # Check timestamp is reasonable (within 1 hour)
        current_time = time.time()
        message_time = message.get('timestamp', 0)
        
        if abs(current_time - message_time) > 3600:  # 1 hour
            return False
        
        return True
    
    def _get_message_id(self, message: Dict[str, Any]) -> str:
        """Generate a unique ID for a message
        
        Args:
            message (Dict[str, Any]): Message to generate ID for
            
        Returns:
            str: Unique message ID
        """
        # Create hash from message content
        message_str = json.dumps(message, sort_keys=True)
        return hashlib.sha256(message_str.encode()).hexdigest()[:16]
    
    def _is_duplicate_message(self, message_id: str) -> bool:
        """Check if message is a duplicate
        
        Args:
            message_id (str): Message ID to check
            
        Returns:
            bool: True if message is duplicate
        """
        # Clean old entries first
        self._clean_message_cache()
        
        return message_id in self.message_cache
    
    def _cache_message_id(self, message_id: str):
        """Cache a message ID to prevent duplicates
        
        Args:
            message_id (str): Message ID to cache
        """
        self.message_cache[message_id] = time.time()
    
    def _clean_message_cache(self):
        """Clean old entries from message cache"""
        current_time = time.time()
        expired_ids = [
            msg_id for msg_id, timestamp in self.message_cache.items()
            if current_time - timestamp > self.cache_timeout
        ]
        
        for msg_id in expired_ids:
            del self.message_cache[msg_id]
    
    # Default message handlers
    
    def _handle_handshake(self, peer, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle handshake message
        
        Args:
            peer: Peer that sent the message
            message (Dict[str, Any]): Handshake message
            
        Returns:
            Optional[Dict[str, Any]]: Handshake response
        """
        self.logger.info(f"Received handshake from {peer.peer_id}")
        
        # Extract peer information
        data = message.get('data', {})
        peer.version = data.get('version', '1.0.0')
        peer.services = data.get('services', [])
        peer.height = data.get('height', 0)
        
        # Create handshake response
        response_data = {
            'version': '1.0.0',
            'services': ['full_node', 'relay'],
            'height': 0,  # Should be actual blockchain height
            'user_agent': 'SmartContract/1.0.0',
            'timestamp': time.time()
        }
        
        return {
            'type': MessageType.HANDSHAKE_ACK.value,
            'version': '1.0.0',
            'timestamp': time.time(),
            'data': response_data
        }
    
    def _handle_ping(self, peer, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle ping message
        
        Args:
            peer: Peer that sent the message
            message (Dict[str, Any]): Ping message
            
        Returns:
            Optional[Dict[str, Any]]: Pong response
        """
        nonce = message.get('data', {}).get('nonce', 0)
        
        return {
            'type': MessageType.PONG.value,
            'version': '1.0.0',
            'timestamp': time.time(),
            'data': {'nonce': nonce}
        }
    
    def _handle_pong(self, peer, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle pong message
        
        Args:
            peer: Peer that sent the message
            message (Dict[str, Any]): Pong message
            
        Returns:
            Optional[Dict[str, Any]]: No response needed
        """
        # Update peer's last seen time
        peer.last_seen = time.time()
        return None
    
    def _handle_block(self, peer, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle block message
        
        Args:
            peer: Peer that sent the message
            message (Dict[str, Any]): Block message
            
        Returns:
            Optional[Dict[str, Any]]: Block acknowledgment
        """
        block_data = message.get('data', {})
        block_hash = block_data.get('hash')
        
        self.logger.info(f"Received block {block_hash} from {peer.peer_id}")
        
        # TODO: Validate and process block
        # This would integrate with the blockchain module
        
        return {
            'type': MessageType.BLOCK_ACK.value,
            'version': '1.0.0',
            'timestamp': time.time(),
            'data': {'block_hash': block_hash, 'status': 'received'}
        }
    
    def _handle_transaction(self, peer, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle transaction message
        
        Args:
            peer: Peer that sent the message
            message (Dict[str, Any]): Transaction message
            
        Returns:
            Optional[Dict[str, Any]]: Transaction acknowledgment
        """
        tx_data = message.get('data', {})
        tx_hash = tx_data.get('hash')
        
        self.logger.info(f"Received transaction {tx_hash} from {peer.peer_id}")
        
        # TODO: Validate and process transaction
        # This would integrate with the blockchain module
        
        return {
            'type': MessageType.TRANSACTION_ACK.value,
            'version': '1.0.0',
            'timestamp': time.time(),
            'data': {'tx_hash': tx_hash, 'status': 'received'}
        }
    
    def _handle_block_request(self, peer, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle block request message
        
        Args:
            peer: Peer that sent the message
            message (Dict[str, Any]): Block request message
            
        Returns:
            Optional[Dict[str, Any]]: Block response or error
        """
        request_data = message.get('data', {})
        block_hash = request_data.get('block_hash')
        block_height = request_data.get('block_height')
        
        self.logger.info(f"Block request from {peer.peer_id}: hash={block_hash}, height={block_height}")
        
        # TODO: Fetch block from blockchain
        # This would integrate with the blockchain module
        
        # For now, return a not found response
        return {
            'type': MessageType.BLOCK_RESPONSE.value,
            'version': '1.0.0',
            'timestamp': time.time(),
            'data': {'status': 'not_found', 'requested_hash': block_hash}
        }
    
    def _handle_peer_list(self, peer, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle peer list message
        
        Args:
            peer: Peer that sent the message
            message (Dict[str, Any]): Peer list message
            
        Returns:
            Optional[Dict[str, Any]]: No response needed
        """
        peer_list = message.get('data', {}).get('peers', [])
        
        self.logger.info(f"Received peer list from {peer.peer_id}: {len(peer_list)} peers")
        
        # TODO: Process peer list for discovery
        # This would integrate with the node discovery module
        
        return None
    
    def create_message(self, message_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new message
        
        Args:
            message_type (str): Type of message to create
            data (Dict[str, Any]): Message data
            
        Returns:
            Dict[str, Any]: Formatted message
        """
        return {
            'type': message_type,
            'version': '1.0.0',
            'timestamp': time.time(),
            'data': data
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get message handling statistics
        
        Returns:
            Dict[str, Any]: Statistics dictionary
        """
        return {
            'messages_received': self.stats.messages_received,
            'messages_sent': self.stats.messages_sent,
            'messages_processed': self.stats.messages_processed,
            'messages_failed': self.stats.messages_failed,
            'bytes_received': self.stats.bytes_received,
            'bytes_sent': self.stats.bytes_sent,
            'last_activity': self.stats.last_activity,
            'cache_size': len(self.message_cache),
            'registered_handlers': len(self.message_handlers)
        }
    
    def reset_statistics(self):
        """Reset message handling statistics"""
        self.stats = MessageStats()
        self.logger.info("Message handler statistics reset")