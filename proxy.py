"""
CipherGate - High-Performance Security Proxy with Zero-Trust Architecture

This module implements the main proxy server that intercepts and secures
data in transit using Zero-Trust principles.
"""

import asyncio
import logging
import time
from typing import Dict, Any, Optional, List
from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, validator
import uvicorn
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from crypto_vault import CryptoVault
from masking_engine import MaskingEngine
from compliance_auditor import ComplianceAuditor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Security configuration
security = HTTPBearer(auto_error=False)

class SecurityProxy:
    """Main security proxy implementing Zero-Trust Architecture"""
    
    def __init__(self):
        self.crypto_vault = CryptoVault()
        self.masking_engine = MaskingEngine()
        self.auditor = ComplianceAuditor()
        self.app = self._create_app()
        
    def _create_app(self) -> FastAPI:
        """Create and configure the FastAPI application"""
        app = FastAPI(
            title="CipherGate Security Proxy",
            description="High-performance security proxy implementing Zero-Trust Architecture",
            version="1.0.0",
            docs_url="/docs",
            redoc_url="/redoc"
        )
        
        # Add CORS middleware
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # Configure based on your needs
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Add security middleware
        app.add_middleware(SecurityMiddleware, proxy=self)
        
        # Health check endpoint
        @app.get("/health")
        async def health_check():
            return {"status": "healthy", "timestamp": time.time()}
            
        # Main proxy endpoint
        @app.post("/api/proxy/{service_path:path}")
        async def proxy_endpoint(
            service_path: str,
            request: Request,
            credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
        ):
            return await self.handle_request(service_path, request, credentials)
            
        return app
    
    async def handle_request(
        self, 
        service_path: str, 
        request: Request, 
        credentials: Optional[HTTPAuthorizationCredentials]
    ) -> Dict[str, Any]:
        """Handle incoming requests with Zero-Trust validation"""
        start_time = time.time()
        
        try:
            # 1. Verify Explicitly - Authenticate and authorize
            user_context = await self._verify_user(credentials)
            
            # 2. Validate request schema
            raw_payload = await request.json()
            validated_payload = self._validate_payload(raw_payload)
            
            # 3. Log access attempt
            self.auditor.log_access_attempt(
                user_id=user_context.get('user_id', 'anonymous'),
                service_path=service_path,
                action='proxy_request',
                payload_size=len(str(raw_payload))
            )
            
            # 4. Apply data masking based on user role
            masked_payload = self.masking_engine.apply_masking(
                validated_payload, 
                user_context.get('role', 'guest')
            )
            
            # Ensure masked_payload is a dict for encryption
            if not isinstance(masked_payload, dict):
                masked_payload = {"data": masked_payload}
            
            # 5. Encrypt sensitive data
            encrypted_payload = self.crypto_vault.encrypt_payload(masked_payload)
            
            # 6. Process the request (simulated service call)
            response = await self._process_service_request(service_path, encrypted_payload)
            
            # 7. Decrypt and mask response
            decrypted_response = self.crypto_vault.decrypt_payload(response)
            masked_response = self.masking_engine.apply_masking(
                decrypted_response,
                user_context.get('role', 'guest')
            )
            
            # Ensure final response is a dict
            if not isinstance(masked_response, dict):
                final_response = {"data": masked_response}
            else:
                final_response = masked_response
            
            # 8. Log successful completion
            self.auditor.log_access_completion(
                user_id=user_context.get('user_id', 'anonymous'),
                service_path=service_path,
                duration=time.time() - start_time,
                success=True,
                session_id=None
            )
            
            return final_response
            
        except Exception as e:
            logger.error(f"Request processing failed: {str(e)}")
            self.auditor.log_access_completion(
                user_id='unknown',
                service_path=service_path,
                duration=time.time() - start_time,
                success=False,
                session_id=None,
                error_message=str(e)
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Request processing failed"
            )
    
    async def _verify_user(self, credentials: Optional[HTTPAuthorizationCredentials]) -> Dict[str, Any]:
        """Verify user authentication and extract context"""
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required"
            )
        
        # In a real implementation, this would validate against an auth service
        token = credentials.credentials
        user_context = self.crypto_vault.validate_token(token)
        
        if not user_context:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token"
            )
            
        return user_context
    
    def _validate_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Validate incoming JSON payload schema"""
        # Basic schema validation
        if not isinstance(payload, dict):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid payload format"
            )
        
        # Add more sophisticated schema validation as needed
        return payload
    
    async def _process_service_request(self, service_path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate processing the request with the target service"""
        # In a real implementation, this would make HTTP requests to the actual service
        await asyncio.sleep(0.1)  # Simulate network delay
        
        return {
            "status": "success",
            "service": service_path,
            "processed_at": time.time(),
            "data": payload
        }


class SecurityMiddleware(BaseHTTPMiddleware):
    """Security middleware implementing Zero-Trust principles"""
    
    def __init__(self, app, proxy: SecurityProxy):
        super().__init__(app)
        self.proxy = proxy
    
    async def dispatch(self, request: Request, call_next):
        # Add security headers
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        return response


if __name__ == "__main__":
    proxy = SecurityProxy()
    
    uvicorn.run(
        proxy.app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
        access_log=True
    )