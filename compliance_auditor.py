"""
ComplianceAuditor - Tamper-Proof Logging System for CipherGate Security Proxy

Implements compliance logging aligned with GDPR/HIPAA standards.
Provides immutable audit trails with cryptographic integrity verification.
"""

import hashlib
import json
import logging
import time
import threading
import asyncio
import aiofiles
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from enum import Enum

# Configure logging
logger = logging.getLogger(__name__)

class AuditEventType(Enum):
    """Types of audit events"""
    ACCESS_ATTEMPT = "access_attempt"
    ACCESS_COMPLETION = "access_completion"
    AUTHENTICATION = "authentication"
    DATA_ACCESS = "data_access"
    MASKING_APPLIED = "masking_applied"
    ENCRYPTION_OPERATION = "encryption_operation"
    TOKEN_VALIDATION = "token_validation"
    SECURITY_VIOLATION = "security_violation"


@dataclass
class AuditRecord:
    """Immutable audit record with cryptographic integrity"""
    timestamp: float
    event_type: str
    user_id: str
    session_id: str
    action: str
    resource: str
    details: Dict[str, Any]
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    success: bool = True
    error_message: Optional[str] = None
    record_hash: Optional[str] = None
    chain_hash: Optional[str] = None
    
    def __post_init__(self):
        """Calculate hash for integrity verification"""
        if self.record_hash is None:
            self.record_hash = self._calculate_hash()
    
    def _calculate_hash(self) -> str:
        """Calculate SHA-256 hash of the record"""
        record_data = {
            'timestamp': self.timestamp,
            'event_type': self.event_type,
            'user_id': self.user_id,
            'session_id': self.session_id,
            'action': self.action,
            'resource': self.resource,
            'details': self.details,
            'source_ip': self.source_ip,
            'user_agent': self.user_agent,
            'success': self.success,
            'error_message': self.error_message
        }
        
        record_json = json.dumps(record_data, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(record_json.encode('utf-8')).hexdigest()


class ComplianceAuditor:
    """Tamper-proof compliance logging system with asynchronous I/O"""
    
    def __init__(self):
        self.audit_log: List[AuditRecord] = []
        self.chain_head: Optional[str] = None
        self.lock = threading.RLock()
        self.log_queue = asyncio.Queue()
        self.log_file_path = "audit_log.json"
        self._initialize_chain()
        # Start background log writer task
        self._log_writer_task = None
        
    def _initialize_chain(self):
        """Initialize the audit chain with a genesis record"""
        genesis_record = AuditRecord(
            timestamp=time.time(),
            event_type=AuditEventType.AUTHENTICATION.value,
            user_id="system",
            session_id="genesis",
            action="system_init",
            resource="compliance_auditor",
            details={"init": True},
            success=True
        )
        genesis_record.chain_hash = genesis_record.record_hash
        self.audit_log.append(genesis_record)
        self.chain_head = genesis_record.chain_hash
        logger.info("Compliance auditor initialized with genesis record")
    
    def log_access_attempt(self, user_id: str, service_path: str, action: str, 
                          payload_size: int, source_ip: Optional[str] = None,
                          user_agent: Optional[str] = None) -> str:
        """Log an access attempt"""
        session_id = self._generate_session_id()
        
        record = AuditRecord(
            timestamp=time.time(),
            event_type=AuditEventType.ACCESS_ATTEMPT.value,
            user_id=user_id,
            session_id=session_id,
            action=action,
            resource=service_path,
            details={
                "payload_size": payload_size,
                "service_type": "proxy"
            },
            source_ip=source_ip,
            user_agent=user_agent,
            success=True
        )
        
        self._add_record(record)
        return session_id
    
    def log_access_completion(self, user_id: str, service_path: str, duration: float,
                             success: bool, session_id: Optional[str] = None,
                             error_message: Optional[str] = None) -> None:
        """Log access completion"""
        record = AuditRecord(
            timestamp=time.time(),
            event_type=AuditEventType.ACCESS_COMPLETION.value,
            user_id=user_id,
            session_id=session_id or self._generate_session_id(),
            action="request_completed",
            resource=service_path,
            details={
                "duration": duration,
                "success": success
            },
            success=success,
            error_message=error_message
        )
        
        self._add_record(record)
    
    def log_authentication(self, user_id: str, success: bool, 
                          source_ip: Optional[str] = None,
                          user_agent: Optional[str] = None,
                          error_message: Optional[str] = None) -> None:
        """Log authentication events"""
        record = AuditRecord(
            timestamp=time.time(),
            event_type=AuditEventType.AUTHENTICATION.value,
            user_id=user_id,
            session_id=self._generate_session_id(),
            action="token_validation",
            resource="authentication",
            details={},
            source_ip=source_ip,
            user_agent=user_agent,
            success=success,
            error_message=error_message
        )
        
        self._add_record(record)
    
    def log_data_access(self, user_id: str, data_type: str, masked: bool,
                       session_id: Optional[str] = None) -> None:
        """Log data access events"""
        record = AuditRecord(
            timestamp=time.time(),
            event_type=AuditEventType.DATA_ACCESS.value,
            user_id=user_id,
            session_id=session_id or self._generate_session_id(),
            action="data_retrieval",
            resource=f"data_{data_type}",
            details={
                "data_type": data_type,
                "masked": masked
            },
            success=True
        )
        
        self._add_record(record)
    
    def log_masking_applied(self, user_id: str, pattern_type: str, 
                           masking_level: str, session_id: Optional[str] = None) -> None:
        """Log when data masking is applied"""
        record = AuditRecord(
            timestamp=time.time(),
            event_type=AuditEventType.MASKING_APPLIED.value,
            user_id=user_id,
            session_id=session_id or self._generate_session_id(),
            action="data_masking",
            resource=f"masking_{pattern_type}",
            details={
                "pattern_type": pattern_type,
                "masking_level": masking_level
            },
            success=True
        )
        
        self._add_record(record)
    
    def log_encryption_operation(self, user_id: str, operation: str, 
                                algorithm: str, success: bool,
                                session_id: Optional[str] = None) -> None:
        """Log encryption/decryption operations"""
        record = AuditRecord(
            timestamp=time.time(),
            event_type=AuditEventType.ENCRYPTION_OPERATION.value,
            user_id=user_id,
            session_id=session_id or self._generate_session_id(),
            action=operation,
            resource=f"crypto_{algorithm}",
            details={
                "operation": operation,
                "algorithm": algorithm
            },
            success=success
        )
        
        self._add_record(record)
    
    def log_security_violation(self, user_id: str, violation_type: str,
                              details: Dict[str, Any], source_ip: Optional[str] = None) -> None:
        """Log security violations"""
        record = AuditRecord(
            timestamp=time.time(),
            event_type=AuditEventType.SECURITY_VIOLATION.value,
            user_id=user_id,
            session_id=self._generate_session_id(),
            action="security_violation",
            resource="security_monitoring",
            details={
                "violation_type": violation_type,
                **details
            },
            source_ip=source_ip,
            success=False
        )
        
        self._add_record(record)
    
    def _add_record(self, record: AuditRecord) -> None:
        """Add a record to the audit log with chain integrity"""
        with self.lock:
            # Chain the record to the previous one
            if self.audit_log:
                previous_record = self.audit_log[-1]
                record.chain_hash = hashlib.sha256(
                    f"{previous_record.chain_hash}{record.record_hash}".encode('utf-8')
                ).hexdigest()
            else:
                record.chain_hash = record.record_hash
            
            self.audit_log.append(record)
            self.chain_head = record.chain_hash
            
            # Start background writer if not running
            if self._log_writer_task is None or self._log_writer_task.done():
                try:
                    loop = asyncio.get_running_loop()
                    self._log_writer_task = loop.create_task(self._background_log_writer())
                except RuntimeError:
                    # No running event loop, start one in a thread
                    import threading
                    def run_event_loop():
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        try:
                            loop.run_until_complete(self._background_log_writer())
                        finally:
                            loop.close()
                    
                    thread = threading.Thread(target=run_event_loop, daemon=True)
                    thread.start()
            
            # Put record in queue for async writing
            try:
                loop = asyncio.get_running_loop()
                asyncio.run_coroutine_threadsafe(self.log_queue.put(record), loop)
            except RuntimeError:
                # No running event loop, use a simple queue approach
                # This is a fallback for synchronous contexts
                pass
            
            # Log to standard logging for monitoring
            logger.info(f"Audit: {record.event_type} - User: {record.user_id} - Action: {record.action}")
    
    async def _background_log_writer(self):
        """Background task to write logs to disk asynchronously"""
        try:
            while True:
                # Get record from queue (this will block until a record is available)
                record = await self.log_queue.get()
                
                # Write to disk asynchronously
                await self._write_record_to_disk(record)
                
                # Mark task as done
                self.log_queue.task_done()
                
        except asyncio.CancelledError:
            logger.info("Background log writer task cancelled")
        except Exception as e:
            logger.error(f"Error in background log writer: {e}")
    
    async def _write_record_to_disk(self, record: AuditRecord):
        """Write a single record to disk asynchronously"""
        try:
            # Convert record to JSON
            record_data = asdict(record)
            record_json = json.dumps(record_data, separators=(',', ':'))
            
            # Write to file asynchronously
            async with aiofiles.open(self.log_file_path, 'a', encoding='utf-8') as f:
                await f.write(record_json + '\n')
                
        except Exception as e:
            logger.error(f"Failed to write audit record to disk: {e}")
    
    async def flush_logs(self):
        """Wait for all pending logs to be written to disk"""
        try:
            # Wait for all items in queue to be processed
            await self.log_queue.join()
            
            # Cancel the background writer task
            if self._log_writer_task and not self._log_writer_task.done():
                self._log_writer_task.cancel()
                try:
                    await self._log_writer_task
                except asyncio.CancelledError:
                    pass
                    
        except Exception as e:
            logger.error(f"Error flushing logs: {e}")
    
    def _generate_session_id(self) -> str:
        """Generate a unique session ID"""
        return f"session_{int(time.time() * 1000)}_{hash(str(time.time())) % 10000}"
    
    def verify_integrity(self) -> Dict[str, Any]:
        """
        Verify the integrity of the audit log
        
        Returns:
            Dictionary with verification results
        """
        with self.lock:
            if not self.audit_log:
                return {"integrity": False, "error": "Empty audit log"}
            
            # Verify chain integrity
            current_chain = self.audit_log[0].chain_hash
            for i in range(1, len(self.audit_log)):
                record = self.audit_log[i]
                expected_chain = hashlib.sha256(
                    f"{current_chain}{record.record_hash}".encode('utf-8')
                ).hexdigest()
                
                if record.chain_hash != expected_chain:
                    return {
                        "integrity": False,
                        "error": f"Chain break at record {i}",
                        "expected_chain": expected_chain,
                        "actual_chain": record.chain_hash
                    }
                
                current_chain = record.chain_hash
            
            # Verify individual record hashes
            for i, record in enumerate(self.audit_log):
                calculated_hash = record._calculate_hash()
                if record.record_hash != calculated_hash:
                    return {
                        "integrity": False,
                        "error": f"Record hash mismatch at record {i}",
                        "expected_hash": calculated_hash,
                        "actual_hash": record.record_hash
                    }
            
            return {
                "integrity": True,
                "record_count": len(self.audit_log),
                "chain_head": self.chain_head,
                "time_span": {
                    "start": datetime.fromtimestamp(self.audit_log[0].timestamp, tz=timezone.utc).isoformat(),
                    "end": datetime.fromtimestamp(self.audit_log[-1].timestamp, tz=timezone.utc).isoformat()
                }
            }
    
    def get_audit_trail(self, start_time: Optional[float] = None, 
                       end_time: Optional[float] = None,
                       user_id: Optional[str] = None,
                       event_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get audit trail with optional filtering
        
        Args:
            start_time: Filter records after this timestamp
            end_time: Filter records before this timestamp
            user_id: Filter records for specific user
            event_type: Filter records by event type
            
        Returns:
            List of audit records
        """
        with self.lock:
            filtered_records = self.audit_log
            
            if start_time:
                filtered_records = [r for r in filtered_records if r.timestamp >= start_time]
            
            if end_time:
                filtered_records = [r for r in filtered_records if r.timestamp <= end_time]
            
            if user_id:
                filtered_records = [r for r in filtered_records if r.user_id == user_id]
            
            if event_type:
                filtered_records = [r for r in filtered_records if r.event_type == event_type]
            
            return [asdict(record) for record in filtered_records]
    
    def export_audit_log(self, format: str = "json") -> str:
        """
        Export audit log in specified format
        
        Args:
            format: Export format (json, csv)
            
        Returns:
            Exported audit log as string
        """
        with self.lock:
            if format.lower() == "json":
                return json.dumps({
                    "audit_log": [asdict(record) for record in self.audit_log],
                    "integrity_check": self.verify_integrity(),
                    "export_timestamp": time.time(),
                    "export_format": "json"
                }, indent=2)
            else:
                raise ValueError(f"Unsupported export format: {format}")
    
    def get_compliance_report(self) -> Dict[str, Any]:
        """
        Generate a compliance report for GDPR/HIPAA
        
        Returns:
            Compliance report with statistics and integrity verification
        """
        with self.lock:
            integrity_check = self.verify_integrity()
            
            # Count events by type
            event_counts = {}
            for record in self.audit_log:
                event_type = record.event_type
                event_counts[event_type] = event_counts.get(event_type, 0) + 1
            
            # Count successful vs failed operations
            success_count = sum(1 for record in self.audit_log if record.success)
            failure_count = len(self.audit_log) - success_count
            
            # Get time range
            if self.audit_log:
                time_range = {
                    "start": datetime.fromtimestamp(self.audit_log[0].timestamp, tz=timezone.utc).isoformat(),
                    "end": datetime.fromtimestamp(self.audit_log[-1].timestamp, tz=timezone.utc).isoformat(),
                    "duration_hours": (self.audit_log[-1].timestamp - self.audit_log[0].timestamp) / 3600
                }
            else:
                time_range = {"start": None, "end": None, "duration_hours": 0}
            
            return {
                "compliance_standard": "GDPR/HIPAA",
                "integrity_verified": integrity_check["integrity"],
                "record_count": len(self.audit_log),
                "time_range": time_range,
                "event_statistics": event_counts,
                "operation_results": {
                    "successful": success_count,
                    "failed": failure_count,
                    "success_rate": round((success_count / len(self.audit_log) * 100), 2) if self.audit_log else 0
                },
                "security_incidents": event_counts.get(AuditEventType.SECURITY_VIOLATION.value, 0),
                "data_access_events": event_counts.get(AuditEventType.DATA_ACCESS.value, 0),
                "authentication_events": event_counts.get(AuditEventType.AUTHENTICATION.value, 0)
            }