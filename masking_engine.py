"""
MaskingEngine - Dynamic Data Masking Module for CipherGate Security Proxy

Implements automatic detection and masking of sensitive patterns (PII/PHI)
including emails, credit cards, SSNs, phone numbers, and addresses.
Masking behavior is role-based to implement least privilege access.
"""

import re
import logging
import json
from typing import Dict, Any, List, Union, Optional, Pattern
from enum import Enum

# Configure logging
logger = logging.getLogger(__name__)

class UserRole(Enum):
    """User roles for role-based masking"""
    ADMIN = "admin"
    USER = "user"
    GUEST = "guest"
    AUDITOR = "auditor"


class MaskingEngine:
    """Dynamic Data Masking engine with pattern detection and role-based masking"""
    
    def __init__(self):
        self.patterns = self._compile_patterns()
        self.masking_rules = self._define_masking_rules()
        
    def _compile_patterns(self) -> Dict[str, Pattern]:
        """Compile regex patterns for sensitive data detection"""
        return {
            'email': re.compile(
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            ),
            'credit_card': re.compile(
                r'\b(?:\d[ -]*?){13,16}\b'
            ),
            'ssn': re.compile(
                r'\b\d{3}[-]?\d{2}[-]?\d{4}\b'
            ),
            'phone': re.compile(
                r'\b(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b'
            ),
            'address': re.compile(
                r'\b\d{1,5}\s\w+\s(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr)\b',
                re.IGNORECASE
            ),
            'ip_address': re.compile(
                r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            ),
            'date_of_birth': re.compile(
                r'\b(?:\d{1,2})[-/](?:\d{1,2})[-/](?:\d{4}|\d{2})\b'
            ),
            'account_number': re.compile(
                r'\b(?:\d[ -]*?){8,17}\b'
            )
        }
    
    def _define_masking_rules(self) -> Dict[str, Dict[UserRole, str]]:
        """Define masking rules based on user roles"""
        return {
            'email': {
                UserRole.ADMIN: 'full',      # user@domain.com
                UserRole.USER: 'partial',    # u***@domain.com
                UserRole.GUEST: 'masked',    # ***@***.com
                UserRole.AUDITOR: 'partial'  # user@domain.com (audit trail)
            },
            'credit_card': {
                UserRole.ADMIN: 'full',      # 1234-5678-9012-3456
                UserRole.USER: 'last_four',  # ****-****-****-3456
                UserRole.GUEST: 'masked',    # ****-****-****-****
                UserRole.AUDITOR: 'last_four' # ****-****-****-3456
            },
            'ssn': {
                UserRole.ADMIN: 'full',      # 123-45-6789
                UserRole.USER: 'last_four',  # ***-**-6789
                UserRole.GUEST: 'masked',    # ***-**-****
                UserRole.AUDITOR: 'last_four' # ***-**-6789
            },
            'phone': {
                UserRole.ADMIN: 'full',      # (555) 123-4567
                UserRole.USER: 'partial',    # (555) ***-4567
                UserRole.GUEST: 'masked',    # ***-***-4567
                UserRole.AUDITOR: 'partial'  # (555) ***-4567
            },
            'address': {
                UserRole.ADMIN: 'full',      # 123 Main Street
                UserRole.USER: 'partial',    # 123 *** Street
                UserRole.GUEST: 'masked',    # *** *** Street
                UserRole.AUDITOR: 'partial'  # 123 *** Street
            },
            'ip_address': {
                UserRole.ADMIN: 'full',      # 192.168.1.1
                UserRole.USER: 'partial',    # 192.168.1.***
                UserRole.GUEST: 'masked',    # ***.***.***.***
                UserRole.AUDITOR: 'full'     # 192.168.1.1 (for security monitoring)
            },
            'date_of_birth': {
                UserRole.ADMIN: 'full',      # 01/15/1985
                UserRole.USER: 'year_only',  # 01/15/****
                UserRole.GUEST: 'masked',    # **/**/****
                UserRole.AUDITOR: 'year_only' # 01/15/****
            },
            'account_number': {
                UserRole.ADMIN: 'full',      # 1234567890123456
                UserRole.USER: 'last_four',  # ************3456
                UserRole.GUEST: 'masked',    # ****************
                UserRole.AUDITOR: 'last_four' # ************3456
            }
        }
    
    def apply_masking(self, data: Union[Dict[str, Any], List[Any], str], role: str) -> Union[Dict[str, Any], List[Any], str]:
        """
        Apply dynamic data masking based on user role
        
        Args:
            data: Data to mask (can be dict, list, or string)
            role: User role (admin, user, guest, auditor)
            
        Returns:
            Masked data
        """
        try:
            user_role = UserRole(role.lower())
        except ValueError:
            logger.warning(f"Unknown role: {role}, defaulting to guest")
            user_role = UserRole.GUEST
        
        return self._mask_data_recursive(data, user_role)
    
    def _mask_data_recursive(self, data: Union[Dict[str, Any], List[Any], str], role: UserRole) -> Union[Dict[str, Any], List[Any], str]:
        """Recursively apply masking to nested data structures"""
        if isinstance(data, dict):
            return {key: self._mask_data_recursive(value, role) for key, value in data.items()}
        elif isinstance(data, list):
            return [self._mask_data_recursive(item, role) for item in data]
        elif isinstance(data, str):
            return self._mask_string(data, role)
        else:
            return data
    
    def _mask_string(self, text: str, role: UserRole) -> str:
        """Apply masking to a string based on detected patterns"""
        masked_text = text
        
        for pattern_name, pattern in self.patterns.items():
            if pattern_name in self.masking_rules:
                rule = self.masking_rules[pattern_name].get(role, 'masked')
                masked_text = self._apply_pattern_masking(masked_text, pattern, rule)
        
        return masked_text
    
    def _apply_pattern_masking(self, text: str, pattern: Pattern, rule: str) -> str:
        """Apply specific masking rule to detected patterns"""
        def mask_match(match: re.Match) -> str:
            matched_text = match.group(0)
            
            if rule == 'full':
                return matched_text
            elif rule == 'masked':
                return '*' * len(matched_text)
            elif rule == 'partial':
                return self._mask_partially(matched_text)
            elif rule == 'last_four':
                return self._mask_to_last_four(matched_text)
            elif rule == 'year_only':
                return self._mask_year_only(matched_text)
            else:
                return '*' * len(matched_text)
        
        return pattern.sub(mask_match, text)
    
    def _mask_partially(self, text: str) -> str:
        """Mask part of the text while preserving some characters"""
        if len(text) <= 2:
            return '*' * len(text)
        
        # Show first and last character, mask the rest
        return text[0] + '*' * (len(text) - 2) + text[-1]
    
    def _mask_to_last_four(self, text: str) -> str:
        """Mask all but the last four characters"""
        if len(text) <= 4:
            return '*' * len(text)
        
        # Show only last four characters
        digits = re.sub(r'[^\d]', '', text)
        if len(digits) <= 4:
            return '*' * len(text)
        
        # Replace all digits except last 4 with *
        result = ''
        digit_count = 0
        for char in reversed(text):
            if char.isdigit():
                if digit_count < 4:
                    result = char + result
                else:
                    result = '*' + result
                digit_count += 1
            else:
                result = char + result
        
        return result
    
    def _mask_year_only(self, text: str) -> str:
        """Mask only the year portion of dates"""
        # For dates in format MM/DD/YYYY or MM-DD-YYYY
        date_pattern = re.compile(r'(\d{1,2})[-/](\d{1,2})[-/](\d{4})')
        
        def replace_year(match: re.Match) -> str:
            month, day, year = match.groups()
            return f"{month}/{day}/****"
        
        return date_pattern.sub(replace_year, text)
    
    def detect_sensitive_data(self, data: Union[Dict[str, Any], List[Any], str]) -> List[Dict[str, Any]]:
        """
        Detect sensitive data patterns in the provided data
        
        Args:
            data: Data to analyze
            
        Returns:
            List of detected sensitive data with locations and types
        """
        detections = []
        
        def analyze_value(value: Any, path: str = ""):
            if isinstance(value, dict):
                for key, val in value.items():
                    new_path = f"{path}.{key}" if path else key
                    analyze_value(val, new_path)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    new_path = f"{path}[{i}]"
                    analyze_value(item, new_path)
            elif isinstance(value, str):
                self._detect_patterns_in_string(value, path, detections)
        
        analyze_value(data)
        return detections
    
    def _detect_patterns_in_string(self, text: str, path: str, detections: List[Dict[str, Any]]):
        """Detect sensitive patterns in a string"""
        for pattern_name, pattern in self.patterns.items():
            matches = pattern.findall(text)
            for match in matches:
                detections.append({
                    "type": pattern_name,
                    "value": match,
                    "path": path,
                    "location": text.find(match),
                    "length": len(match)
                })
    
    def get_masking_statistics(self, original_data: Union[Dict[str, Any], List[Any], str], 
                              masked_data: Union[Dict[str, Any], List[Any], str]) -> Dict[str, Any]:
        """
        Generate statistics about the masking process
        
        Args:
            original_data: Original unmasked data
            masked_data: Masked data
            
        Returns:
            Statistics about the masking process
        """
        original_str = json.dumps(original_data, separators=(',', ':'))
        masked_str = json.dumps(masked_data, separators=(',', ':'))
        
        # Count asterisks to measure masking intensity
        asterisk_count = masked_str.count('*')
        total_chars = len(masked_str)
        masking_percentage = (asterisk_count / total_chars * 100) if total_chars > 0 else 0
        
        # Detect sensitive data in original
        detections = self.detect_sensitive_data(original_data)
        
        return {
            "original_length": len(original_str),
            "masked_length": len(masked_str),
            "asterisks_used": asterisk_count,
            "masking_percentage": round(masking_percentage, 2),
            "sensitive_patterns_detected": len(detections),
            "pattern_types": list(set(detection["type"] for detection in detections)),
            "detections": detections
        }
    
    def validate_masking_integrity(self, original_data: Union[Dict[str, Any], List[Any], str],
                                 masked_data: Union[Dict[str, Any], List[Any], str]) -> bool:
        """
        Validate that masking preserved data structure integrity
        
        Args:
            original_data: Original data structure
            masked_data: Masked data structure
            
        Returns:
            True if structure is preserved, False otherwise
        """
        def compare_structure(orig, masked):
            if type(orig) != type(masked):
                return False
            
            if isinstance(orig, dict):
                if set(orig.keys()) != set(masked.keys()):
                    return False
                return all(compare_structure(orig[k], masked[k]) for k in orig.keys())
            
            elif isinstance(orig, list):
                if len(orig) != len(masked):
                    return False
                return all(compare_structure(o, m) for o, m in zip(orig, masked))
            
            elif isinstance(orig, str):
                # For strings, just ensure they're both strings
                return isinstance(masked, str)
            
            else:
                # For other types, they should be equal
                return orig == masked
        
        return compare_structure(original_data, masked_data)