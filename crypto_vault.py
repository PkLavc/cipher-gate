"""
CryptoVault - Cryptographic Layer for CipherGate Security Proxy

Implements AES-256-GCM encryption for "Data at Rest" and HMAC-SHA256 
for integrity verification. Provides secure key management and 
token validation.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

# Configure logging
logger = logging.getLogger(__name__)

class CryptoVault:
    """Cryptographic vault implementing AES-256-GCM and HMAC-SHA256"""
    
    def __init__(self):
        self.aes_key = self._generate_aes_key()
        self.hmac_key = self._generate_hmac_key()
        self.rsa_private_key = self._generate_rsa_keypair()
        self.rsa_public_key = self.rsa_private_key.public_key()
        
        # Token storage for session management
        self.active_tokens: Dict[str, Dict[str, Any]] = {}
        
    def _generate_aes_key(self) -> bytes:
        """Generate a 256-bit AES key"""
        return secrets.token_bytes(32)  # 256 bits
    
    def _generate_hmac_key(self) -> bytes:
        """Generate a 256-bit HMAC key"""
        return secrets.token_bytes(32)  # 256 bits
    
    def _generate_rsa_keypair(self):
        """Generate RSA key pair for token signing"""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
    
    def encrypt_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Encrypt payload using AES-256-GCM with integrity verification
        
        Args:
            payload: Dictionary containing data to encrypt
            
        Returns:
            Dictionary with encrypted data and metadata
        """
        try:
            # Serialize payload to JSON bytes
            plaintext = json.dumps(payload, separators=(',', ':')).encode('utf-8')
            
            # Generate random nonce for AES-GCM
            nonce = secrets.token_bytes(12)  # 96-bit nonce
            
            # Encrypt with AES-256-GCM
            aesgcm = AESGCM(self.aes_key)
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)
            
            # Generate HMAC for integrity verification
            mac = self._generate_hmac(ciphertext)
            
            # Return encrypted payload with metadata
            return {
                "version": "1.0",
                "algorithm": "AES-256-GCM",
                "nonce": base64.b64encode(nonce).decode('utf-8'),
                "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
                "hmac": base64.b64encode(mac).decode('utf-8'),
                "timestamp": time.time()
            }
            
        except Exception as e:
            logger.error(f"Encryption failed: {str(e)}")
            raise ValueError("Payload encryption failed")
    
    def decrypt_payload(self, encrypted_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decrypt payload using AES-256-GCM with integrity verification
        
        Args:
            encrypted_payload: Dictionary containing encrypted data
            
        Returns:
            Dictionary with decrypted data
        """
        try:
            # Validate payload structure
            required_fields = ['nonce', 'ciphertext', 'hmac', 'version']
            if not all(field in encrypted_payload for field in required_fields):
                raise ValueError("Invalid encrypted payload format")
            
            # Decode base64 fields
            nonce = base64.b64decode(encrypted_payload['nonce'])
            ciphertext = base64.b64decode(encrypted_payload['ciphertext'])
            received_mac = base64.b64decode(encrypted_payload['hmac'])
            
            # Verify integrity with HMAC
            calculated_mac = self._generate_hmac(ciphertext)
            if not self._verify_hmac(calculated_mac, received_mac):
                raise ValueError("Integrity verification failed")
            
            # Decrypt with AES-256-GCM
            aesgcm = AESGCM(self.aes_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            # Parse JSON payload
            return json.loads(plaintext.decode('utf-8'))
            
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            raise ValueError("Payload decryption failed")
    
    def _generate_hmac(self, data: bytes) -> bytes:
        """Generate HMAC-SHA256 for data integrity"""
        return hmac.new(self.hmac_key, data, hashlib.sha256).digest()
    
    def _verify_hmac(self, calculated_mac: bytes, received_mac: bytes) -> bool:
        """Verify HMAC using constant-time comparison"""
        return hmac.compare_digest(calculated_mac, received_mac)
    
    def generate_token(self, user_id: str, role: str, expires_in: int = 3600) -> str:
        """
        Generate a signed authentication token
        
        Args:
            user_id: Unique identifier for the user
            role: User role (e.g., 'admin', 'user', 'guest')
            expires_in: Token expiration time in seconds (default: 1 hour)
            
        Returns:
            Base64-encoded signed token
        """
        try:
            # Create token payload
            token_payload = {
                "user_id": user_id,
                "role": role,
                "issued_at": time.time(),
                "expires_at": time.time() + expires_in,
                "token_id": secrets.token_hex(16)
            }
            
            # Serialize and sign token
            token_data = json.dumps(token_payload, separators=(',', ':')).encode('utf-8')
            signature = self._sign_data(token_data)
            
            # Combine token data and signature
            signed_token = {
                "payload": base64.b64encode(token_data).decode('utf-8'),
                "signature": base64.b64encode(signature).decode('utf-8'),
                "algorithm": "RSA-SHA256"
            }
            
            # Store token for validation
            token_id = token_payload["token_id"]
            self.active_tokens[token_id] = {
                "user_id": user_id,
                "role": role,
                "expires_at": token_payload["expires_at"],
                "issued_at": token_payload["issued_at"]
            }
            
            return base64.b64encode(
                json.dumps(signed_token, separators=(',', ':')).encode('utf-8')
            ).decode('utf-8')
            
        except Exception as e:
            logger.error(f"Token generation failed: {str(e)}")
            raise ValueError("Token generation failed")
    
    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate and extract user context from token
        
        Args:
            token: Base64-encoded signed token
            
        Returns:
            User context dictionary if valid, None if invalid
        """
        try:
            # Decode token
            token_data = json.loads(base64.b64decode(token.encode('utf-8')).decode('utf-8'))
            
            # Extract components
            payload_b64 = token_data.get('payload')
            signature_b64 = token_data.get('signature')
            
            if not payload_b64 or not signature_b64:
                return None
            
            # Decode payload and signature
            payload = base64.b64decode(payload_b64)
            signature = base64.b64decode(signature_b64)
            
            # Verify signature
            if not self._verify_signature(payload, signature):
                return None
            
            # Parse payload
            token_payload = json.loads(payload.decode('utf-8'))
            token_id = token_payload.get('token_id')
            
            # Check if token is active and not expired
            if token_id not in self.active_tokens:
                return None
            
            token_info = self.active_tokens[token_id]
            current_time = time.time()
            
            if current_time > token_info['expires_at']:
                # Remove expired token
                del self.active_tokens[token_id]
                return None
            
            return {
                "user_id": token_payload['user_id'],
                "role": token_payload['role'],
                "token_id": token_id,
                "issued_at": token_payload['issued_at'],
                "expires_at": token_payload['expires_at']
            }
            
        except Exception as e:
            logger.error(f"Token validation failed: {str(e)}")
            return None
    
    def _sign_data(self, data: bytes) -> bytes:
        """Sign data using RSA private key"""
        return self.rsa_private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    
    def _verify_signature(self, data: bytes, signature: bytes) -> bool:
        """Verify signature using RSA public key"""
        try:
            self.rsa_public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
    
    def revoke_token(self, token: str) -> bool:
        """Revoke a token by removing it from active tokens"""
        try:
            token_data = json.loads(base64.b64decode(token.encode('utf-8')).decode('utf-8'))
            payload_b64 = token_data.get('payload')
            
            if not payload_b64:
                return False
            
            payload = base64.b64decode(payload_b64)
            token_payload = json.loads(payload.decode('utf-8'))
            token_id = token_payload.get('token_id')
            
            if token_id in self.active_tokens:
                del self.active_tokens[token_id]
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Token revocation failed: {str(e)}")
            return False
    
    def get_key_info(self) -> Dict[str, Any]:
        """Get information about cryptographic keys (for debugging/monitoring)"""
        return {
            "aes_key_length": len(self.aes_key) * 8,  # bits
            "hmac_key_length": len(self.hmac_key) * 8,  # bits
            "rsa_key_size": self.rsa_private_key.key_size,
            "active_tokens": len(self.active_tokens),
            "algorithm": {
                "encryption": "AES-256-GCM",
                "integrity": "HMAC-SHA256",
                "signature": "RSA-SHA256"
            }
        }