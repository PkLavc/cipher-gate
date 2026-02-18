"""
Security-Focused Unit Tests for CipherGate Security Proxy

Tests security vulnerabilities and validates Zero-Trust principles:
- Unauthenticated access attempts
- Data integrity verification
- Role-based access control
- Cryptographic operations
- Compliance logging
"""

import pytest
import json
import time
from typing import Dict, Any

from crypto_vault import CryptoVault
from masking_engine import MaskingEngine, UserRole
from compliance_auditor import ComplianceAuditor


class TestSecurityVulnerabilities:
    """Test security vulnerabilities and Zero-Trust principles"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.crypto_vault = CryptoVault()
        self.masking_engine = MaskingEngine()
        self.auditor = ComplianceAuditor()
    
    def test_unauthenticated_access_blocked(self):
        """Test that unauthenticated requests are blocked"""
        # Simulate unauthenticated request
        credentials = None
        
        # This should raise an exception in the proxy
        with pytest.raises(Exception):
            # In a real test, this would call the proxy endpoint
            # For now, we test the token validation directly
            result = self.crypto_vault.validate_token(None)
            assert result is None
    
    def test_invalid_token_rejected(self):
        """Test that invalid tokens are rejected"""
        invalid_token = "invalid_token_string"
        
        result = self.crypto_vault.validate_token(invalid_token)
        assert result is None
    
    def test_data_integrity_verification(self):
        """Test that data integrity is verified during encryption/decryption"""
        test_data = {"sensitive": "data", "user": "test@example.com"}
        
        # Encrypt data
        encrypted = self.crypto_vault.encrypt_payload(test_data)
        
        # Verify encryption structure
        assert "ciphertext" in encrypted
        assert "hmac" in encrypted
        assert "nonce" in encrypted
        
        # Decrypt data
        decrypted = self.crypto_vault.decrypt_payload(encrypted)
        
        # Verify data integrity
        assert decrypted == test_data
    
    def test_data_integrity_compromise_detection(self):
        """Test that compromised data is detected"""
        test_data = {"sensitive": "data"}
        
        # Encrypt data
        encrypted = self.crypto_vault.encrypt_payload(test_data)
        
        # Tamper with the ciphertext
        original_ciphertext = encrypted["ciphertext"]
        tampered_ciphertext = original_ciphertext[:-10] + "tampered_data"
        encrypted["ciphertext"] = tampered_ciphertext
        
        # Attempt to decrypt should fail
        with pytest.raises(ValueError, match="Integrity verification failed"):
            self.crypto_vault.decrypt_payload(encrypted)
    
    def test_role_based_access_control(self):
        """Test role-based data masking"""
        sensitive_data = {
            "user_email": "john.doe@example.com",
            "credit_card": "1234-5678-9012-3456",
            "ssn": "123-45-6789",
            "phone": "(555) 123-4567"
        }
        
        # Test admin access (full data)
        admin_masked = self.masking_engine.apply_masking(sensitive_data, "admin")
        assert admin_masked["user_email"] == "john.doe@example.com"
        assert admin_masked["credit_card"] == "1234-5678-9012-3456"
        
        # Test user access (partial masking)
        user_masked = self.masking_engine.apply_masking(sensitive_data, "user")
        assert user_masked["user_email"].startswith("j") and user_masked["user_email"].endswith("@example.com")
        assert user_masked["credit_card"].endswith("3456")
        
        # Test guest access (full masking)
        guest_masked = self.masking_engine.apply_masking(sensitive_data, "guest")
        assert guest_masked["user_email"] == "***@***.com"
        assert guest_masked["credit_card"] == "****-****-****-****"
    
    def test_sensitive_data_detection(self):
        """Test automatic detection of sensitive data patterns"""
        test_data = {
            "message": "Contact me at user@domain.com or call 555-123-4567",
            "address": "123 Main Street, Anytown, USA",
            "ssn": "123-45-6789"
        }
        
        detections = self.masking_engine.detect_sensitive_data(test_data)
        
        # Verify detections
        detected_types = [d["type"] for d in detections]
        assert "email" in detected_types
        assert "phone" in detected_types
        assert "ssn" in detected_types
    
    def test_compliance_logging_integrity(self):
        """Test that compliance logs maintain cryptographic integrity"""
        # Log some events
        self.auditor.log_access_attempt("test_user", "/api/test", "test_action", 100)
        self.auditor.log_authentication("test_user", True)
        self.auditor.log_data_access("test_user", "user_data", True)
        
        # Verify log integrity
        integrity_result = self.auditor.verify_integrity()
        assert integrity_result["integrity"] is True
        assert integrity_result["record_count"] == 4  # Including genesis record
    
    def test_compliance_logging_chain_break_detection(self):
        """Test detection of log chain breaks"""
        # Log some events
        self.auditor.log_access_attempt("test_user", "/api/test", "test_action", 100)
        original_chain = self.auditor.chain_head
        
        # Simulate tampering by modifying the audit log directly
        # (This would be impossible in a real secure system, but we test the detection)
        if self.auditor.audit_log:
            self.auditor.audit_log[-1].record_hash = "tampered_hash"
        
        # Verify integrity check detects the tampering
        integrity_result = self.auditor.verify_integrity()
        assert integrity_result["integrity"] is False
        assert "Record hash mismatch" in integrity_result["error"]
    
    def test_encryption_key_security(self):
        """Test that encryption keys are properly generated and secured"""
        vault1 = CryptoVault()
        vault2 = CryptoVault()
        
        # Each vault should have unique keys
        assert vault1.aes_key != vault2.aes_key
        assert vault1.hmac_key != vault2.hmac_key
        
        # Keys should be proper length
        assert len(vault1.aes_key) == 32  # 256 bits
        assert len(vault1.hmac_key) == 32  # 256 bits
    
    def test_token_expiration(self):
        """Test that expired tokens are properly rejected"""
        # Generate a token with short expiration
        token = self.crypto_vault.generate_token("test_user", "user", expires_in=1)
        
        # Token should be valid initially
        result = self.crypto_vault.validate_token(token)
        assert result is not None
        assert result["user_id"] == "test_user"
        
        # Wait for expiration
        time.sleep(2)
        
        # Token should be invalid after expiration
        result = self.crypto_vault.validate_token(token)
        assert result is None
    
    def test_masking_structure_preservation(self):
        """Test that data masking preserves structure integrity"""
        original_data = {
            "user": {
                "name": "John Doe",
                "email": "john@example.com",
                "address": {
                    "street": "123 Main St",
                    "city": "Anytown"
                }
            },
            "orders": [
                {"id": 1, "amount": 100.50},
                {"id": 2, "amount": 250.75}
            ]
        }
        
        masked_data = self.masking_engine.apply_masking(original_data, "user")
        
        # Verify structure is preserved
        assert isinstance(masked_data, dict)
        assert "user" in masked_data
        assert "orders" in masked_data
        assert isinstance(masked_data["user"], dict)
        assert isinstance(masked_data["orders"], list)
        
        # Verify masking was applied
        assert masked_data["user"]["email"] != original_data["user"]["email"]
    
    def test_security_violation_logging(self):
        """Test that security violations are properly logged"""
        self.auditor.log_security_violation(
            "suspicious_user", 
            "unauthorized_access", 
            {"attempted_resource": "/api/admin", "source_ip": "192.168.1.100"}
        )
        
        # Verify violation was logged
        violations = self.auditor.get_audit_trail(
            event_type="security_violation"
        )
        assert len(violations) == 1
        assert violations[0]["user_id"] == "suspicious_user"
        assert violations[0]["event_type"] == "security_violation"
        assert not violations[0]["success"]  # Security violations should be marked as failed
    
    def test_compliance_report_generation(self):
        """Test generation of compliance reports"""
        # Log various events
        self.auditor.log_access_attempt("user1", "/api/data", "read", 500)
        self.auditor.log_data_access("user1", "personal_data", True)
        self.auditor.log_encryption_operation("user1", "encrypt", "AES-256-GCM", True)
        
        # Generate compliance report
        report = self.auditor.get_compliance_report()
        
        # Verify report structure
        assert "compliance_standard" in report
        assert "integrity_verified" in report
        assert "record_count" in report
        assert "event_statistics" in report
        assert "operation_results" in report
        
        # Verify compliance standard
        assert report["compliance_standard"] == "GDPR/HIPAA"
        assert report["integrity_verified"] is True


class TestPerformanceAndScalability:
    """Test performance and scalability aspects"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.crypto_vault = CryptoVault()
        self.masking_engine = MaskingEngine()
    
    def test_encryption_performance(self):
        """Test encryption performance with large payloads"""
        large_data = {"data": "x" * 10000}  # 10KB of data
        
        start_time = time.time()
        encrypted = self.crypto_vault.encrypt_payload(large_data)
        encryption_time = time.time() - start_time
        
        start_time = time.time()
        decrypted = self.crypto_vault.decrypt_payload(encrypted)
        decryption_time = time.time() - start_time
        
        # Verify performance (should be under 1 second for 10KB)
        assert encryption_time < 1.0
        assert decryption_time < 1.0
        assert decrypted == large_data
    
    def test_masking_performance(self):
        """Test masking performance with complex data"""
        complex_data = {
            "users": [{"email": f"user{i}@example.com", "ssn": f"{i:03d}-45-6789"} for i in range(100)],
            "messages": [f"Contact {i}@domain.com for info" for i in range(50)]
        }
        
        start_time = time.time()
        masked = self.masking_engine.apply_masking(complex_data, "user")
        masking_time = time.time() - start_time
        
        # Verify performance (should be under 1 second for complex data)
        assert masking_time < 1.0
        
        # Verify masking was applied
        assert masked["users"][0]["email"] != complex_data["users"][0]["email"]


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])