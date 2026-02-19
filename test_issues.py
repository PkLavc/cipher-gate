#!/usr/bin/env python3
"""
Test script to identify logical failure points in CipherGate
"""

from crypto_vault import CryptoVault
from masking_engine import MaskingEngine
from compliance_auditor import ComplianceAuditor
import threading
import time

def test_key_persistence():
    """Test 1: Key persistence issue"""
    print("=== TEST 1: Key Persistence Issue ===")
    
    # Create first vault and encrypt data
    vault1 = CryptoVault()
    test_data = {'test': 'data', 'secret': 'sensitive information'}
    encrypted = vault1.encrypt_payload(test_data)
    print(f"Encrypted with vault1: {encrypted['ciphertext'][:50]}...")
    
    # Create second vault instance (simulating application restart)
    vault2 = CryptoVault()
    print("Created new vault2 instance (simulating restart)")
    
    # Try to decrypt with new vault
    try:
        decrypted = vault2.decrypt_payload(encrypted)
        print("OK Decryption successful with vault2")
        print(f"Decrypted data: {decrypted}")
    except Exception as e:
        print(f"X Decryption failed with vault2: {str(e)}")
        print("BUG CONFIRMED: Keys are not persistent across restarts!")

def test_pattern_overlap():
    """Test 2: Pattern detection overlap"""
    print("\n=== TEST 2: Pattern Detection Overlap ===")
    
    engine = MaskingEngine()
    test_text = 'My credit card is 1234-5678-9012-3456 and my account number is 9876543210987654'
    
    print(f"Original text: {test_text}")
    print("Patterns detected:")
    
    detections = engine.detect_sensitive_data(test_text)
    for detection in detections:
        print(f"  - {detection['type']}: '{detection['value']}' at position {detection['location']}")
    
    # Check for overlapping patterns
    credit_card_detections = [d for d in detections if d['type'] == 'credit_card']
    account_number_detections = [d for d in detections if d['type'] == 'account_number']
    
    if credit_card_detections and account_number_detections:
        cc_pos = credit_card_detections[0]['location']
        cc_len = credit_card_detections[0]['length']
        acc_pos = account_number_detections[0]['location']
        acc_len = account_number_detections[0]['length']
        
        # Check if they overlap
        if (cc_pos < acc_pos + acc_len and acc_pos < cc_pos + cc_len):
            print("BUG CONFIRMED: Overlapping pattern detection detected!")
            print(f"  Credit card: position {cc_pos}, length {cc_len}")
            print(f"  Account number: position {acc_pos}, length {acc_len}")
    
    print(f"\nMasked text (user role): {engine.apply_masking(test_text, 'user')}")

def test_thread_safety():
    """Test 3: Thread safety"""
    print("\n=== TEST 3: Thread Safety ===")
    
    auditor = ComplianceAuditor()
    
    def log_events(thread_id):
        for i in range(20):
            auditor.log_authentication(f'user_{thread_id}', True, source_ip=f'192.168.1.{thread_id}')
            time.sleep(0.001)
    
    # Create multiple threads
    threads = []
    for i in range(10):
        thread = threading.Thread(target=log_events, args=(i,))
        threads.append(thread)
    
    print("Starting 10 threads to log authentication events...")
    
    # Start all threads
    for thread in threads:
        thread.start()
    
    # Wait for completion
    for thread in threads:
        thread.join()
    
    print("All threads completed. Checking audit log integrity...")
    
    # Check integrity
    integrity = auditor.verify_integrity()
    print(f"Integrity check: {integrity['integrity']}")
    print(f"Total records: {integrity['record_count']}")
    
    if not integrity['integrity']:
        print("BUG CONFIRMED: Audit log integrity compromised under concurrent access!")
        print(f"Error: {integrity.get('error', 'Unknown error')}")
    else:
        print("V Audit log integrity maintained under concurrent access")

if __name__ == "__main__":
    print("CipherGate Logical Failure Point Tests")
    print("=" * 50)
    
    test_key_persistence()
    test_pattern_overlap()
    test_thread_safety()
    
    print("\n" + "=" * 50)
    print("Test completed. Review results above for identified bugs.")