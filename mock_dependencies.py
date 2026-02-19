"""
Mock dependencies for CipherGate simulation when real dependencies are not available
"""

import json
import time
import secrets
import hashlib
from typing import Dict, Any, Optional, List, Union
from enum import Enum


class HTTPException(Exception):
    """Mock HTTPException"""
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


class HTTPBearer:
    """Mock HTTPBearer"""
    def __init__(self, auto_error: bool = True):
        self.auto_error = auto_error


class HTTPAuthorizationCredentials:
    """Mock HTTPAuthorizationCredentials"""
    def __init__(self, credentials: str):
        self.credentials = credentials


class BaseModel:
    """Mock Pydantic BaseModel"""
    pass


class validator:
    """Mock Pydantic validator"""
    def __init__(self, *fields, **kwargs):
        self.fields = fields
        self.kwargs = kwargs
    
    def __call__(self, func):
        return func


class FastAPI:
    """Mock FastAPI"""
    def __init__(self, **kwargs):
        self.title = kwargs.get('title', '')
        self.description = kwargs.get('description', '')
        self.version = kwargs.get('version', '')
        self.routes = []
    
    def get(self, path: str, **kwargs):
        def decorator(func):
            self.routes.append(('GET', path, func))
            return func
        return decorator
    
    def post(self, path: str, **kwargs):
        def decorator(func):
            self.routes.append(('POST', path, func))
            return func
        return decorator


class Request:
    """Mock Request"""
    def __init__(self, body: Dict[str, Any]):
        self._body = body
    
    async def json(self):
        return self._body


class JSONResponse:
    """Mock JSONResponse"""
    def __init__(self, content: Dict[str, Any]):
        self.content = content


class BaseHTTPMiddleware:
    """Mock BaseHTTPMiddleware"""
    def __init__(self, app):
        self.app = app


class CORSMiddleware:
    """Mock CORSMiddleware"""
    def __init__(self, app, **kwargs):
        self.app = app


class Depends:
    """Mock Depends"""
    def __init__(self, dependency):
        self.dependency = dependency


class status:
    """Mock status codes"""
    HTTP_200_OK = 200
    HTTP_400_BAD_REQUEST = 400
    HTTP_401_UNAUTHORIZED = 401
    HTTP_500_INTERNAL_SERVER_ERROR = 500


class uvicorn:
    """Mock uvicorn"""
    @staticmethod
    def run(app, **kwargs):
        print(f"Mock uvicorn server starting on {kwargs.get('host', '0.0.0.0')}:{kwargs.get('port', 8000)}")
        print("Mock server is running (simulation mode)")
        print("Available endpoints:")
        for method, path, func in app.routes:
            print(f"  {method} {path}")
        print("\nSimulation server ready - use Ctrl+C to stop")


# Mock cryptography functionality
class AESGCM:
    """Mock AESGCM for encryption"""
    def __init__(self, key: bytes):
        self.key = key
    
    def encrypt(self, nonce: bytes, plaintext: bytes, associated_data: Optional[bytes]) -> bytes:
        # Simple mock encryption - just combine nonce + plaintext + key hash
        return nonce + plaintext + hashlib.sha256(self.key).digest()[:16]
    
    def decrypt(self, nonce: bytes, ciphertext: bytes, associated_data: Optional[bytes]) -> bytes:
        # Simple mock decryption
        if len(ciphertext) < len(nonce) + 16:
            raise ValueError("Invalid ciphertext")
        return ciphertext[len(nonce):-16]


class RSAKeyPair:
    """Mock RSA key pair"""
    def __init__(self):
        self.private_key = secrets.token_bytes(32)
        self.public_key = secrets.token_bytes(32)
    
    def sign(self, data: bytes, padding, hash_algorithm) -> bytes:
        return hashlib.sha256(data + self.private_key).digest()
    
    def verify(self, signature: bytes, data: bytes, padding, hash_algorithm) -> bool:
        return hashlib.sha256(data + self.private_key).digest() == signature


# Mock asyncio
import asyncio as _asyncio

class MockAsyncio:
    """Mock asyncio for file operations"""
    
    @staticmethod
    async def sleep(seconds: float):
        time.sleep(seconds)
    
    @staticmethod
    async def get_running_loop():
        return _asyncio.get_event_loop()
    
    @staticmethod
    def run_until_complete(coro):
        return _asyncio.run(coro)
    
    @staticmethod
    def new_event_loop():
        return _asyncio.new_event_loop()
    
    @staticmethod
    def set_event_loop(loop):
        _asyncio.set_event_loop(loop)


# Mock aiofiles
class MockAioFiles:
    """Mock aiofiles for async file operations"""
    
    class AsyncContextManager:
        def __init__(self, file_path: str, mode: str, encoding: str):
            self.file_path = file_path
            self.mode = mode
            self.encoding = encoding
            self.file = None
        
        async def __aenter__(self):
            self.file = open(self.file_path, self.mode, encoding=self.encoding)
            return self
        
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            if self.file:
                self.file.close()
        
        async def write(self, data: str):
            if self.file:
                self.file.write(data)
    
    @staticmethod
    async def open(file_path: str, mode: str = 'r', encoding: str = 'utf-8'):
        return MockAioFiles.AsyncContextManager(file_path, mode, encoding)


# Replace imports
import sys
import types

# Create proper module objects with __dict__
fastapi_module = types.ModuleType('fastapi')
fastapi_module.__dict__.update({
    'FastAPI': FastAPI,
    'HTTPException': HTTPException,
    'HTTPBearer': HTTPBearer,
    'HTTPAuthorizationCredentials': HTTPAuthorizationCredentials,
    'Request': Request,
    'Depends': Depends,
    'status': status,
    'JSONResponse': JSONResponse
})

fastapi_cors_module = types.ModuleType('fastapi.middleware.cors')
fastapi_cors_module.__dict__.update({
    'CORSMiddleware': CORSMiddleware
})

fastapi_security_module = types.ModuleType('fastapi.security')
fastapi_security_module.__dict__.update({
    'HTTPBearer': HTTPBearer,
    'HTTPAuthorizationCredentials': HTTPAuthorizationCredentials
})

pydantic_module = types.ModuleType('pydantic')
pydantic_module.__dict__.update({
    'BaseModel': BaseModel,
    'validator': validator
})

starlette_base_module = types.ModuleType('starlette.middleware.base')
starlette_base_module.__dict__.update({
    'BaseHTTPMiddleware': BaseHTTPMiddleware
})

starlette_responses_module = types.ModuleType('starlette.responses')
starlette_responses_module.__dict__.update({
    'JSONResponse': JSONResponse
})

# Replace modules
sys.modules['fastapi'] = fastapi_module
sys.modules['fastapi.middleware.cors'] = fastapi_cors_module
sys.modules['fastapi.security'] = fastapi_security_module
sys.modules['pydantic'] = pydantic_module
sys.modules['starlette.middleware.base'] = starlette_base_module
sys.modules['starlette.responses'] = starlette_responses_module

# Create module objects for non-module types
uvicorn_module = types.ModuleType('uvicorn')
uvicorn_module.__dict__.update({'run': uvicorn.run})

asyncio_module = types.ModuleType('asyncio')
asyncio_module.__dict__.update(MockAsyncio.__dict__)

aiofiles_module = types.ModuleType('aiofiles')
aiofiles_module.__dict__.update({'open': MockAioFiles.open})

sys.modules['uvicorn'] = uvicorn_module
sys.modules['asyncio'] = asyncio_module
sys.modules['aiofiles'] = aiofiles_module

print("Mock dependencies loaded successfully")