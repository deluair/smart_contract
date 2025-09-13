"""Network Protocol for Blockchain Communication

This module defines the network protocol, message types, and serialization
for blockchain peer-to-peer communication.
"""

import json
import time
import struct
import socket
import hashlib
from enum import Enum
from typing import Dict, Any, Optional, Union
from dataclasses import dataclass
import logging

class MessageType(Enum):
    """Network message types"""
    # Connection management
    HANDSHAKE = "handshake"
    HANDSHAKE_ACK = "handshake_ack"
    PING = "ping"
    PONG = "pong"
    DISCONNECT = "disconnect"
    
    # Blockchain data
    BLOCK = "block"
    BLOCK_ACK = "block_ack"
    BLOCK_REQUEST = "block_request"
    BLOCK_RESPONSE = "block_response"
    BLOCK_HEADER = "block_header"
    
    # Transactions
    TRANSACTION = "transaction"
    TRANSACTION_ACK = "transaction_ack"
    TRANSACTION_REQUEST = "transaction_request"
    MEMPOOL_REQUEST = "mempool_request"
    
    # Peer discovery
    PEER_LIST = "peer_list"
    PEER_LIST_REQUEST = "peer_list_request"
    PEER_LIST_RESPONSE = "peer_list_response"
    
    # Synchronization
    SYNC_REQUEST = "sync_request"
    SYNC_RESPONSE = "sync_response"
    CHAIN_INFO = "chain_info"
    
    # Smart contracts
    CONTRACT_DEPLOY = "contract_deploy"
    CONTRACT_CALL = "contract_call"
    CONTRACT_EVENT = "contract_event"
    
    # Oracle data
    ORACLE_REQUEST = "oracle_request"
    ORACLE_RESPONSE = "oracle_response"
    PRICE_UPDATE = "price_update"

@dataclass
class ProtocolConfig:
    """Protocol configuration"""
    version: str = "1.0.0"
    magic_bytes: bytes = b'\x12\x34\x56\x78'
    max_message_size: int = 32 * 1024 * 1024  # 32MB
    compression_enabled: bool = True
    encryption_enabled: bool = False
    checksum_enabled: bool = True

class NetworkProtocol:
    """Handles network protocol operations"""
    
    def __init__(self, config: ProtocolConfig = None):
        self.config = config or ProtocolConfig()
        self.logger = logging.getLogger(__name__)
    
    def create_message(self, message_type: MessageType, data: Dict[str, Any], 
                      nonce: int = None) -> Dict[str, Any]:
        """Create a protocol message
        
        Args:
            message_type (MessageType): Type of message
            data (Dict[str, Any]): Message data
            nonce (int): Optional nonce for the message
            
        Returns:
            Dict[str, Any]: Formatted protocol message
        """
        message = {
            'type': message_type.value,
            'version': self.config.version,
            'timestamp': time.time(),
            'data': data
        }
        
        if nonce is not None:
            message['nonce'] = nonce
        
        # Add checksum if enabled
        if self.config.checksum_enabled:
            message['checksum'] = self._calculate_checksum(message)
        
        return message
    
    def create_handshake_message(self, version: str, services: list, height: int) -> Dict[str, Any]:
        """Create a handshake message
        
        Args:
            version (str): Node version
            services (list): Supported services
            height (int): Current blockchain height
            
        Returns:
            Dict[str, Any]: Handshake message
        """
        data = {
            'version': version,
            'services': services,
            'height': height,
            'user_agent': f'SmartContract/{version}',
            'timestamp': time.time()
        }
        
        return self.create_message(MessageType.HANDSHAKE, data)
    
    def create_ping_message(self, nonce: int = None) -> Dict[str, Any]:
        """Create a ping message
        
        Args:
            nonce (int): Optional nonce for ping
            
        Returns:
            Dict[str, Any]: Ping message
        """
        if nonce is None:
            nonce = int(time.time() * 1000000) % (2**32)  # Microsecond timestamp
        
        data = {'nonce': nonce}
        return self.create_message(MessageType.PING, data, nonce)
    
    def create_pong_message(self, nonce: int) -> Dict[str, Any]:
        """Create a pong message
        
        Args:
            nonce (int): Nonce from the ping message
            
        Returns:
            Dict[str, Any]: Pong message
        """
        data = {'nonce': nonce}
        return self.create_message(MessageType.PONG, data, nonce)
    
    def create_block_message(self, block_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a block message
        
        Args:
            block_data (Dict[str, Any]): Block data
            
        Returns:
            Dict[str, Any]: Block message
        """
        return self.create_message(MessageType.BLOCK, block_data)
    
    def create_transaction_message(self, transaction_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a transaction message
        
        Args:
            transaction_data (Dict[str, Any]): Transaction data
            
        Returns:
            Dict[str, Any]: Transaction message
        """
        return self.create_message(MessageType.TRANSACTION, transaction_data)
    
    def create_peer_list_request(self) -> Dict[str, Any]:
        """Create a peer list request message
        
        Returns:
            Dict[str, Any]: Peer list request message
        """
        return self.create_message(MessageType.PEER_LIST_REQUEST, {})
    
    def create_peer_list_response(self, peers: list) -> Dict[str, Any]:
        """Create a peer list response message
        
        Args:
            peers (list): List of peer addresses
            
        Returns:
            Dict[str, Any]: Peer list response message
        """
        data = {'peers': peers}
        return self.create_message(MessageType.PEER_LIST_RESPONSE, data)
    
    def send_message(self, socket: socket.socket, message: Dict[str, Any]) -> bool:
        """Send a message over a socket
        
        Args:
            socket (socket.socket): Socket to send message on
            message (Dict[str, Any]): Message to send
            
        Returns:
            bool: True if message was sent successfully
        """
        try:
            # Serialize message
            serialized = self._serialize_message(message)
            
            # Check message size
            if len(serialized) > self.config.max_message_size:
                self.logger.error(f"Message too large: {len(serialized)} bytes")
                return False
            
            # Send message length first (4 bytes)
            length_bytes = struct.pack('!I', len(serialized))
            socket.send(length_bytes)
            
            # Send message data
            socket.send(serialized)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send message: {e}")
            return False
    
    def receive_message(self, socket: socket.socket, timeout: int = 30) -> Optional[Dict[str, Any]]:
        """Receive a message from a socket
        
        Args:
            socket (socket.socket): Socket to receive message from
            timeout (int): Receive timeout in seconds
            
        Returns:
            Optional[Dict[str, Any]]: Received message or None
        """
        try:
            # Set socket timeout
            socket.settimeout(timeout)
            
            # Receive message length (4 bytes)
            length_bytes = self._receive_exact(socket, 4)
            if not length_bytes:
                return None
            
            message_length = struct.unpack('!I', length_bytes)[0]
            
            # Check message size
            if message_length > self.config.max_message_size:
                self.logger.error(f"Message too large: {message_length} bytes")
                return None
            
            # Receive message data
            message_data = self._receive_exact(socket, message_length)
            if not message_data:
                return None
            
            # Deserialize message
            message = self._deserialize_message(message_data)
            
            # Validate message
            if self._validate_message(message):
                return message
            else:
                self.logger.warning("Received invalid message")
                return None
                
        except socket.timeout:
            self.logger.debug("Socket timeout while receiving message")
            return None
        except Exception as e:
            self.logger.error(f"Failed to receive message: {e}")
            return None
    
    def _receive_exact(self, socket: socket.socket, length: int) -> Optional[bytes]:
        """Receive exact number of bytes from socket
        
        Args:
            socket (socket.socket): Socket to receive from
            length (int): Number of bytes to receive
            
        Returns:
            Optional[bytes]: Received bytes or None
        """
        data = b''
        while len(data) < length:
            chunk = socket.recv(length - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    
    def _serialize_message(self, message: Dict[str, Any]) -> bytes:
        """Serialize a message to bytes
        
        Args:
            message (Dict[str, Any]): Message to serialize
            
        Returns:
            bytes: Serialized message
        """
        # Convert to JSON
        json_str = json.dumps(message, separators=(',', ':'), sort_keys=True)
        
        # Encode to bytes
        message_bytes = json_str.encode('utf-8')
        
        # Add compression if enabled
        if self.config.compression_enabled and len(message_bytes) > 1024:
            try:
                import gzip
                compressed = gzip.compress(message_bytes)
                # Only use compression if it actually reduces size
                if len(compressed) < len(message_bytes):
                    # Add compression flag
                    return b'\x01' + compressed
            except ImportError:
                pass
        
        # No compression flag
        return b'\x00' + message_bytes
    
    def _deserialize_message(self, data: bytes) -> Dict[str, Any]:
        """Deserialize bytes to a message
        
        Args:
            data (bytes): Serialized message data
            
        Returns:
            Dict[str, Any]: Deserialized message
        """
        # Check compression flag
        compression_flag = data[0]
        message_data = data[1:]
        
        # Decompress if needed
        if compression_flag == 1:
            try:
                import gzip
                message_data = gzip.decompress(message_data)
            except ImportError:
                raise ValueError("Compressed message received but gzip not available")
        
        # Decode from bytes and parse JSON
        json_str = message_data.decode('utf-8')
        return json.loads(json_str)
    
    def _validate_message(self, message: Dict[str, Any]) -> bool:
        """Validate a received message
        
        Args:
            message (Dict[str, Any]): Message to validate
            
        Returns:
            bool: True if message is valid
        """
        # Check required fields
        required_fields = ['type', 'version', 'timestamp']
        for field in required_fields:
            if field not in message:
                return False
        
        # Check message type
        message_type = message.get('type')
        valid_types = [mt.value for mt in MessageType]
        if message_type not in valid_types:
            return False
        
        # Check version compatibility
        version = message.get('version')
        if not self._is_version_compatible(version):
            return False
        
        # Check timestamp (within reasonable range)
        timestamp = message.get('timestamp', 0)
        current_time = time.time()
        if abs(current_time - timestamp) > 3600:  # 1 hour tolerance
            return False
        
        # Verify checksum if present
        if 'checksum' in message:
            expected_checksum = message.pop('checksum')
            calculated_checksum = self._calculate_checksum(message)
            message['checksum'] = expected_checksum  # Restore checksum
            
            if expected_checksum != calculated_checksum:
                return False
        
        return True
    
    def _is_version_compatible(self, version: str) -> bool:
        """Check if a version is compatible
        
        Args:
            version (str): Version to check
            
        Returns:
            bool: True if version is compatible
        """
        # Simple version compatibility check
        # In a real implementation, this would be more sophisticated
        try:
            major, minor, patch = version.split('.')
            our_major, our_minor, our_patch = self.config.version.split('.')
            
            # Same major version is compatible
            return major == our_major
        except:
            return False
    
    def _calculate_checksum(self, message: Dict[str, Any]) -> str:
        """Calculate checksum for a message
        
        Args:
            message (Dict[str, Any]): Message to calculate checksum for
            
        Returns:
            str: Calculated checksum
        """
        # Create a copy without checksum field
        message_copy = {k: v for k, v in message.items() if k != 'checksum'}
        
        # Serialize and hash
        json_str = json.dumps(message_copy, separators=(',', ':'), sort_keys=True)
        return hashlib.sha256(json_str.encode()).hexdigest()[:16]
    
    def get_protocol_info(self) -> Dict[str, Any]:
        """Get protocol information
        
        Returns:
            Dict[str, Any]: Protocol information
        """
        return {
            'version': self.config.version,
            'max_message_size': self.config.max_message_size,
            'compression_enabled': self.config.compression_enabled,
            'encryption_enabled': self.config.encryption_enabled,
            'checksum_enabled': self.config.checksum_enabled,
            'supported_message_types': [mt.value for mt in MessageType]
        }