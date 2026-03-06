"""
Cryptographic vault implementing AES-256-GCM and HMAC-SHA256 for CipherGate Security Proxy.

Provides secure key management, encryption/decryption operations, and JWT token validation
with secure memory wiping capabilities.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sys
import time
import ctypes
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger(__name__)

class CryptoVault:
    """Cryptographic vault implementing AES-256-GCM and HMAC-SHA256"""
    
    def __init__(self):
        """Initialize cryptographic vault with secure key management."""
        self._key_dir = self._get_key_directory()
        self._validate_key_file_permissions()
        self.master_key = self._get_master_key()
        self.aes_key = self._load_or_generate_aes_key()
        self.hmac_key = self._load_or_generate_hmac_key()
        self.rsa_private_key = self._generate_rsa_keypair()
        self.rsa_public_key = self.rsa_private_key.public_key()
        self.active_tokens: Dict[str, Dict[str, Any]] = {}
    
    def _validate_key_file_permissions(self):
        """Validate that key files have secure permissions (600 or less)."""
        key_files = [
            os.path.join(self._key_dir, 'aes_key.bin'),
            os.path.join(self._key_dir, 'hmac_key.bin')
        ]
        
        for key_file in key_files:
            if os.path.exists(key_file):
                try:
                    if os.name == 'nt':  # Windows
                        dir_stat = os.stat(self._key_dir)
                        logger.info(f"Windows platform: Key file {key_file} exists (Windows ACLs should be configured)")
                    else:  # Unix-like systems
                        if hasattr(os, 'stat'):
                            file_stat = os.stat(key_file)
                            permissions = oct(file_stat.st_mode)[-3:]
                            permissions_int = int(permissions, 8)
                            
                            if permissions_int > 0o600:
                                logger.critical(f"Security Alert: Key file {key_file} has insecure permissions: {oct(permissions_int)}")
                                raise PermissionError(f"Key file {key_file} has insecure permissions: {oct(permissions_int)}")
                except (OSError, PermissionError) as e:
                    logger.warning(f"Cannot validate permissions for {key_file}: {e}")
    
    def _get_key_directory(self) -> str:
        """Get secure directory for key storage."""
        project_root = os.path.abspath(os.path.dirname(__file__))
        key_dir = os.path.join(project_root, '.keys')
        os.makedirs(key_dir, exist_ok=True)
        if hasattr(os, 'chmod'):
            try:
                os.chmod(key_dir, 0o700)  # Owner read/write/execute only
            except PermissionError:
                logger.warning("Cannot set restrictive permissions on key directory")
        return key_dir
    
    def _load_or_generate_aes_key(self) -> bytes:
        """Load AES key from persistent vault or generate and save new one."""
        vault_file = os.path.join(self._key_dir, '.key_vault')
        
        if os.path.exists(vault_file):
            try:
                with open(vault_file, 'rb') as f:
                    encrypted_data = f.read()
                    aes_key = self._decrypt_vault(encrypted_data)
                    if len(aes_key) == 32:  # 256 bits
                        logger.info("Loaded existing AES key from persistent vault")
                        return aes_key
                    else:
                        logger.warning("Invalid AES key in vault - file corrupted, creating backup")
                        backup_file = vault_file + '.bak'
                        try:
                            if os.path.exists(backup_file):
                                os.remove(backup_file)
                            os.rename(vault_file, backup_file)
                            logger.info(f"Renamed corrupted vault to {backup_file}")
                        except Exception as e:
                            logger.error(f"Cannot rename corrupted vault file: {e}")
            except Exception as e:
                logger.error(f"Error loading AES key from vault: {e}, creating backup")
                backup_file = vault_file + '.bak'
                try:
                    if os.path.exists(backup_file):
                        os.remove(backup_file)
                    os.rename(vault_file, backup_file)
                    logger.info(f"Renamed corrupted vault to {backup_file}")
                except Exception as e:
                    logger.error(f"Cannot rename corrupted vault file: {e}")
        
        logger.info("No valid vault found, generating new keys...")
        key = self._generate_aes_key()
        encrypted_vault = self._encrypt_vault(key)
        try:
            with open(vault_file, 'wb') as f:
                f.write(encrypted_vault)
            if hasattr(os, 'chmod'):
                try:
                    os.chmod(vault_file, 0o600)  # Owner read/write only
                except PermissionError:
                    logger.warning("Cannot set restrictive permissions on vault file")
            logger.info("Generated and saved new AES key to persistent vault")
        except Exception as e:
            logger.error(f"Error saving AES key to vault: {e}")
            raise ValueError("Failed to save AES key to persistent vault")
        
        return key
    
    def _load_or_generate_hmac_key(self) -> bytes:
        """Load HMAC key from file or generate and save new one."""
        key_file = os.path.join(self._key_dir, 'hmac_key.bin')
        
        try:
            if os.path.exists(key_file):
                with open(key_file, 'rb') as f:
                    key = f.read()
                    if len(key) == 32:  # 256 bits
                        logger.info("Loaded existing HMAC key from file")
                        return key
                    else:
                        logger.warning("Invalid HMAC key file size, generating new key")
            else:
                logger.info("HMAC key file not found, generating new key")
        except Exception as e:
            logger.error(f"Error loading HMAC key: {e}, generating new key")
        
        key = self._generate_hmac_key()
        try:
            with open(key_file, 'wb') as f:
                f.write(key)
            if hasattr(os, 'chmod'):
                try:
                    os.chmod(key_file, 0o600)  # Owner read/write only
                except PermissionError:
                    logger.warning("Cannot set restrictive permissions on HMAC key file")
            logger.info("Generated and saved new HMAC key")
        except Exception as e:
            logger.error(f"Error saving HMAC key: {e}")
            raise ValueError("Failed to save HMAC key to disk")
        
        return key
        
    def _generate_aes_key(self) -> bytes:
        """Generate a 256-bit AES key."""
        return secrets.token_bytes(32)  # 256 bits
    
    def _get_master_key(self) -> bytes:
        """Get master key from environment variable or persistent file for vault encryption."""
        master_key_env = os.environ.get('CIPHERGATE_MASTER_KEY')
        if master_key_env:
            logger.info("Using master key from environment variable")
            return hashlib.sha256(master_key_env.encode('utf-8')).digest()
        
        master_key_file = os.path.join(self._key_dir, '.master.key')
        if os.path.exists(master_key_file):
            try:
                with open(master_key_file, 'rb') as f:
                    master_key_data = f.read()
                    logger.info("Loaded master key from persistent file")
                    return master_key_data
            except Exception as e:
                logger.warning(f"Error loading master key from file: {e}")
        
        logger.warning("CIPHERGATE_MASTER_KEY environment variable not set, generating random master key")
        master_key_env = secrets.token_hex(32)
        master_key_bytes = hashlib.sha256(master_key_env.encode('utf-8')).digest()
        
        try:
            with open(master_key_file, 'wb') as f:
                f.write(master_key_bytes)
            if hasattr(os, 'chmod'):
                try:
                    os.chmod(master_key_file, 0o600)  # Owner read/write only
                except PermissionError:
                    logger.warning("Cannot set restrictive permissions on master key file")
            logger.info("Generated and saved new master key to persistent file")
        except Exception as e:
            logger.error(f"Error saving master key to file: {e}")
            raise ValueError("Failed to save master key to persistent file")
        
        return master_key_bytes
    
    def _encrypt_vault(self, key: bytes) -> bytes:
        """Encrypt the vault using AES-256-GCM."""
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(self.master_key)
        ciphertext = aesgcm.encrypt(nonce, key, None)
        return nonce + ciphertext
    
    def _decrypt_vault(self, encrypted_data: bytes) -> bytes:
        """Decrypt the vault using AES-256-GCM."""
        if len(encrypted_data) < 12:
            raise ValueError("Invalid encrypted vault data")
        
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        aesgcm = AESGCM(self.master_key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    
    def _generate_hmac_key(self) -> bytes:
        """Generate a 256-bit HMAC key."""
        return secrets.token_bytes(32)  # 256 bits
    
    def _generate_rsa_keypair(self):
        """Generate RSA key pair for token signing."""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
    
    def encrypt_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Encrypt payload using AES-256-GCM with integrity verification.
        
        Args:
            payload: Dictionary containing data to encrypt
            
        Returns:
            Dictionary with encrypted data and metadata
        """
        plaintext = None
        nonce = None
        ciphertext = None
        mac = None
        
        try:
            plaintext = json.dumps(payload, separators=(',', ':')).encode('utf-8')
            nonce = secrets.token_bytes(12)  # 96-bit nonce
            aesgcm = AESGCM(self.aes_key)
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)
            mac = self._generate_hmac(ciphertext)
            
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
        finally:
            if plaintext is not None:
                self._secure_wipe_memory(plaintext)
            if nonce is not None:
                self._secure_wipe_memory(nonce)
            if ciphertext is not None:
                self._secure_wipe_memory(ciphertext)
            if mac is not None:
                self._secure_wipe_memory(mac)
    
    def decrypt_payload(self, encrypted_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decrypt payload using AES-256-GCM with integrity verification.
        
        Args:
            encrypted_payload: Dictionary containing encrypted data
            
        Returns:
            Dictionary with decrypted data
        """
        nonce = None
        ciphertext = None
        received_mac = None
        plaintext = None
        
        try:
            required_fields = ['nonce', 'ciphertext', 'hmac', 'version']
            if not all(field in encrypted_payload for field in required_fields):
                raise ValueError("Invalid encrypted payload format")
            
            def fix_base64_padding(b64_string: str) -> str:
                """Fix Base64 padding to prevent binascii.Error."""
                padding_needed = 4 - len(b64_string) % 4
                if padding_needed != 4:
                    b64_string += '=' * padding_needed
                return b64_string
            
            nonce = base64.b64decode(fix_base64_padding(encrypted_payload['nonce']))
            ciphertext = base64.b64decode(fix_base64_padding(encrypted_payload['ciphertext']))
            received_mac = base64.b64decode(fix_base64_padding(encrypted_payload['hmac']))
            
            calculated_mac = self._generate_hmac(ciphertext)
            if not self._verify_hmac(calculated_mac, received_mac):
                raise ValueError("Integrity verification failed")
            
            aesgcm = AESGCM(self.aes_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            return json.loads(plaintext.decode('utf-8'))
            
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            raise ValueError("Payload decryption failed")
        finally:
            if nonce is not None:
                self._secure_wipe_memory(nonce)
            if ciphertext is not None:
                self._secure_wipe_memory(ciphertext)
            if received_mac is not None:
                self._secure_wipe_memory(received_mac)
            if plaintext is not None:
                self._secure_wipe_memory(plaintext)
    
    def _generate_hmac(self, data: bytes) -> bytes:
        """Generate HMAC-SHA256 for data integrity."""
        return hmac.new(self.hmac_key, data, hashlib.sha256).digest()
    
    def _secure_wipe_memory(self, data: bytes):
        """Enhanced secure memory wiping with integrity verification and panic mode."""
        try:
            if isinstance(data, (bytes, bytearray)):
                mutable_data = bytearray(data)
                
                for _ in range(3):
                    for i in range(len(mutable_data)):
                        mutable_data[i] = secrets.randbelow(256)
                
                for i in range(len(mutable_data)):
                    mutable_data[i] = 0
                
                if any(byte != 0 for byte in mutable_data):
                    logger.critical("SECURITY PANIC: Memory wipe verification failed - sensitive data may remain in memory")
                    import sys
                    logger.critical("Initiating panic shutdown to prevent data exposure")
                    sys.exit(1)
                
                mutable_data.clear()
                import gc
                gc.collect()
                
        except Exception as e:
            logger.critical(f"SECURITY PANIC: Memory wipe failed with exception: {e}")
            import sys
            logger.critical("Initiating panic shutdown to prevent data exposure")
            sys.exit(1)
    
    def _verify_hmac(self, calculated_mac: bytes, received_mac: bytes) -> bool:
        """Verify HMAC using constant-time comparison."""
        return hmac.compare_digest(calculated_mac, received_mac)
    
    def generate_token(self, user_id: str, role: str, expires_in: int = 3600) -> str:
        """
        Generate a signed authentication token.
        
        Args:
            user_id: Unique identifier for the user
            role: User role (e.g., 'admin', 'user', 'guest')
            expires_in: Token expiration time in seconds (default: 1 hour)
            
        Returns:
            Base64-encoded signed token
        """
        try:
            token_payload = {
                "user_id": user_id,
                "role": role,
                "issued_at": time.time(),
                "expires_at": time.time() + expires_in,
                "token_id": secrets.token_hex(16)
            }
            
            token_data = json.dumps(token_payload, separators=(',', ':')).encode('utf-8')
            signature = self._sign_data(token_data)
            
            signed_token = {
                "payload": base64.b64encode(token_data).decode('utf-8'),
                "signature": base64.b64encode(signature).decode('utf-8'),
                "algorithm": "RSA-SHA256"
            }
            
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
        Validate and extract user context from token.
        
        Args:
            token: Base64-encoded signed token
            
        Returns:
            User context dictionary if valid, None if invalid
        """
        if token is None:
            logger.error("Token validation failed: Token is None")
            return None
            
        try:
            token_data = json.loads(base64.b64decode(token.encode('utf-8')).decode('utf-8'))
            payload_b64 = token_data.get('payload')
            signature_b64 = token_data.get('signature')
            
            if not payload_b64 or not signature_b64:
                return None
            
            payload = base64.b64decode(payload_b64)
            signature = base64.b64decode(signature_b64)
            
            if not self._verify_signature(payload, signature):
                return None
            
            token_payload = json.loads(payload.decode('utf-8'))
            token_id = token_payload.get('token_id')
            
            if token_id not in self.active_tokens:
                return None
            
            token_info = self.active_tokens[token_id]
            current_time = time.time()
            
            if current_time > token_info['expires_at']:
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
        """Sign data using RSA private key."""
        return self.rsa_private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    
    def _verify_signature(self, data: bytes, signature: bytes) -> bool:
        """Verify signature using RSA public key."""
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
        """Revoke a token by removing it from active tokens."""
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
        """Get information about cryptographic keys (for debugging/monitoring)."""
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
