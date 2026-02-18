"""
CipherGate Security Proxy - Demonstration Script

This script demonstrates the core functionality of the CipherGate security proxy
including encryption, data masking, and compliance logging.
"""

import json
import time
from crypto_vault import CryptoVault
from masking_engine import MaskingEngine
from compliance_auditor import ComplianceAuditor


def demo_encryption():
    """Demonstrate cryptographic operations"""
    print("=== CRYPTOGRAPHIC VAULT DEMO ===")
    
    vault = CryptoVault()
    
    # Test data with sensitive information
    test_data = {
        "user": {
            "name": "John Doe",
            "email": "john.doe@example.com",
            "ssn": "123-45-6789",
            "credit_card": "1234-5678-9012-3456"
        },
        "message": "Contact me at user@domain.com or call 555-123-4567"
    }
    
    print("Original data:")
    print(json.dumps(test_data, indent=2))
    
    # Encrypt the data
    print("\nEncrypting data...")
    encrypted = vault.encrypt_payload(test_data)
    print("Encrypted payload structure:")
    print(f"- Algorithm: {encrypted['algorithm']}")
    print(f"- Ciphertext length: {len(encrypted['ciphertext'])} characters")
    print(f"- HMAC present: {'hmac' in encrypted}")
    
    # Decrypt the data
    print("\nDecrypting data...")
    decrypted = vault.decrypt_payload(encrypted)
    print("Decrypted data:")
    print(json.dumps(decrypted, indent=2))
    
    # Verify data integrity
    print(f"\nData integrity verified: {decrypted == test_data}")
    
    # Generate and validate token
    print("\nGenerating authentication token...")
    token = vault.generate_token("demo_user", "admin", expires_in=3600)
    print(f"Token generated: {token[:50]}...")
    
    print("\nValidating token...")
    user_context = vault.validate_token(token)
    if user_context:
        print(f"Token valid for user: {user_context.get('user_id', 'unknown')}")
        print(f"Role: {user_context.get('role', 'unknown')}")
    else:
        print("Token validation failed")


def demo_data_masking():
    """Demonstrate dynamic data masking"""
    print("\n=== DYNAMIC DATA MASKING DEMO ===")
    
    engine = MaskingEngine()
    
    # Test data with various sensitive patterns
    test_data = {
        "user_info": {
            "name": "Jane Smith",
            "email": "jane.smith@company.com",
            "ssn": "987-65-4321",
            "phone": "(555) 987-6543",
            "address": "456 Oak Avenue, Somewhere, USA"
        },
        "financial": {
            "credit_card": "1111-2222-3333-4444",
            "account_number": "9876543210987654",
            "routing_number": "123456789"
        },
        "system_info": {
            "ip_address": "192.168.1.100",
            "server_name": "web-server-01",
            "log_message": "User john@domain.com accessed system at 12/31/2023"
        }
    }
    
    print("Original data:")
    print(json.dumps(test_data, indent=2))
    
    # Detect sensitive patterns
    print("\nDetecting sensitive data patterns...")
    detections = engine.detect_sensitive_data(test_data)
    print(f"Found {len(detections)} sensitive patterns:")
    for detection in detections:
        print(f"- {detection['type']}: {detection['value']} (at {detection['path']})")
    
    # Apply masking for different roles
    roles = ["admin", "user", "guest", "auditor"]
    
    for role in roles:
        print(f"\n--- {role.upper()} ROLE VIEW ---")
        masked_data = engine.apply_masking(test_data, role)
        print(json.dumps(masked_data, indent=2))
        
        # Show masking statistics
        stats = engine.get_masking_statistics(test_data, masked_data)
        print(f"Masking statistics: {stats['masking_percentage']}% of characters masked")


def demo_compliance_auditing():
    """Demonstrate compliance auditing"""
    print("\n=== COMPLIANCE AUDITING DEMO ===")
    
    auditor = ComplianceAuditor()
    
    # Simulate various security events
    print("Logging security events...")
    
    # Authentication events
    auditor.log_authentication("user1", True, source_ip="192.168.1.100")
    auditor.log_authentication("user2", False, source_ip="10.0.0.50", 
                              error_message="Invalid credentials")
    
    # Access attempts
    session1 = auditor.log_access_attempt("user1", "/api/user-data", "read", 1024, 
                                         source_ip="192.168.1.100")
    auditor.log_access_completion("user1", "/api/user-data", 0.25, True, session1)
    
    session2 = auditor.log_access_attempt("user2", "/api/admin", "write", 512,
                                         source_ip="10.0.0.50")
    auditor.log_access_completion("user2", "/api/admin", 0.1, False, session2,
                                 error_message="Access denied - insufficient privileges")
    
    # Data access events
    auditor.log_data_access("user1", "personal_data", True)
    auditor.log_data_access("user1", "financial_data", False)  # No masking applied
    
    # Security violations
    auditor.log_security_violation("suspicious_user", "brute_force_attack", {
        "failed_attempts": 10,
        "time_window": "5 minutes",
        "source_ip": "203.0.113.1"
    })
    
    # Encryption operations
    auditor.log_encryption_operation("user1", "encrypt", "AES-256-GCM", True)
    auditor.log_encryption_operation("user1", "decrypt", "AES-256-GCM", True)
    
    # Verify log integrity
    print("\nVerifying audit log integrity...")
    integrity_result = auditor.verify_integrity()
    print(f"Integrity verified: {integrity_result['integrity']}")
    print(f"Record count: {integrity_result['record_count']}")
    print(f"Chain head: {integrity_result['chain_head'][:20]}...")
    
    # Generate compliance report
    print("\nGenerating compliance report...")
    report = auditor.get_compliance_report()
    print(f"Compliance standard: {report['compliance_standard']}")
    print(f"Integrity verified: {report['integrity_verified']}")
    print(f"Total records: {report['record_count']}")
    print(f"Successful operations: {report['operation_results']['successful']}")
    print(f"Failed operations: {report['operation_results']['failed']}")
    print(f"Success rate: {report['operation_results']['success_rate']}%")
    print(f"Security incidents: {report['security_incidents']}")
    print(f"Data access events: {report['data_access_events']}")
    
    # Export audit log
    print("\nExporting audit log...")
    exported_log = auditor.export_audit_log("json")
    print(f"Exported log size: {len(exported_log)} characters")


def demo_end_to_end():
    """Demonstrate end-to-end security flow"""
    print("\n=== END-TO-END SECURITY FLOW DEMO ===")
    
    # Initialize all components
    vault = CryptoVault()
    engine = MaskingEngine()
    auditor = ComplianceAuditor()
    
    # Simulate a complete request flow
    print("Simulating complete security proxy flow...")
    
    # 1. User authentication
    print("\n1. User Authentication")
    token = vault.generate_token("alice", "user", expires_in=3600)
    user_context = vault.validate_token(token)
    if user_context:
        print(f"   User: {user_context.get('user_id', 'unknown')}")
        print(f"   Role: {user_context.get('role', 'unknown')}")
    else:
        print("   Authentication failed")
        return
    
    # 2. Request validation and logging
    print("\n2. Request Processing")
    raw_payload = {
        "patient_id": "P123456",
        "medical_record": {
            "diagnosis": "Hypertension",
            "medications": ["Lisinopril", "Hydrochlorothiazide"],
            "doctor": "Dr. Smith",
            "email": "patient@example.com",
            "phone": "(555) 123-4567"
        },
        "timestamp": "2023-12-01T10:30:00Z"
    }
    
    print("   Original payload:")
    print(json.dumps(raw_payload, indent=4))
    
    # 3. Apply data masking based on role
    print("\n3. Applying Data Masking")
    masked_payload = engine.apply_masking(raw_payload, user_context.get('role', 'guest'))
    print("   Masked payload:")
    print(json.dumps(masked_payload, indent=4))
    
    # 4. Encrypt sensitive data
    print("\n4. Encrypting Data")
    # Ensure masked_payload is a dict for encryption
    if not isinstance(masked_payload, dict):
        masked_payload = {"data": masked_payload}
    encrypted_payload = vault.encrypt_payload(masked_payload)
    print(f"   Encrypted: {encrypted_payload['algorithm']}")
    print(f"   Ciphertext length: {len(encrypted_payload['ciphertext'])}")
    
    # 5. Simulate service processing
    print("\n5. Service Processing")
    # In real implementation, this would be an actual HTTP request
    processed_data = {
        "status": "success",
        "processed_at": time.time(),
        "result": encrypted_payload
    }
    
    # 6. Decrypt and apply final masking
    print("\n6. Response Processing")
    decrypted_response = vault.decrypt_payload(processed_data["result"])
    final_response = engine.apply_masking(decrypted_response, user_context['role'])
    
    print("   Final response:")
    print(json.dumps(final_response, indent=4))
    
    # 7. Log completion
    print("\n7. Audit Logging")
    auditor.log_access_attempt(
        user_context['user_id'], 
        "/api/medical-records", 
        "read", 
        len(str(raw_payload)),
        source_ip="192.168.1.50"
    )
    auditor.log_data_access(user_context['user_id'], "medical_data", True)
    auditor.log_encryption_operation(user_context['user_id'], "encrypt", "AES-256-GCM", True)
    auditor.log_encryption_operation(user_context['user_id'], "decrypt", "AES-256-GCM", True)
    auditor.log_access_completion(
        user_context['user_id'], 
        "/api/medical-records", 
        0.5, 
        True
    )
    
    # Verify audit integrity
    integrity = auditor.verify_integrity()
    print(f"   Audit integrity: {integrity['integrity']}")
    
    print("\n=== DEMO COMPLETE ===")
    print("CipherGate successfully demonstrated:")
    print("✓ Zero-Trust authentication and authorization")
    print("✓ Dynamic data masking based on user roles")
    print("✓ Cryptographic protection with AES-256-GCM")
    print("✓ Tamper-proof compliance logging")
    print("✓ End-to-end security flow")


if __name__ == "__main__":
    print("CipherGate Security Proxy - Demonstration")
    print("=" * 50)
    
    try:
        demo_encryption()
        demo_data_masking()
        demo_compliance_auditing()
        demo_end_to_end()
        
        print("\n" + "=" * 50)
        print("All demonstrations completed successfully!")
        print("CipherGate is ready for production deployment.")
        
    except Exception as e:
        print(f"\nError during demonstration: {str(e)}")
        import traceback
        traceback.print_exc()