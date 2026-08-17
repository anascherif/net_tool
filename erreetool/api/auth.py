"""
Authentication and Authorization for API Server.

Provides JWT-based authentication with role-based access control.
"""
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional
from pathlib import Path

from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT Configuration
SECRET_KEY = os.getenv("ERREETOOL_API_SECRET", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 1 week

# In-memory user store (replace with database in production)
_users_db: dict = {}

# Role permissions
ROLE_PERMISSIONS = {
    "admin": ["*"],
    "analyst": [
        "assessment:create",
        "assessment:read",
        "assessment:list",
        "campaign:create",
        "campaign:read",
        "campaign:list",
        "campaign:update",
        "skill:read",
        "skill:list",
        "skill:execute",
        "memory:read",
        "memory:list",
    ],
    "viewer": [
        "assessment:read",
        "assessment:list",
        "campaign:read",
        "campaign:list",
        "skill:read",
        "skill:list",
        "memory:read",
        "memory:list",
    ],
}


class UserInDB(BaseModel):
    id: str
    username: str
    email: str
    hashed_password: str
    full_name: Optional[str] = None
    role: str = "analyst"
    is_active: bool = True
    created_at: datetime
    last_login: Optional[datetime] = None


def get_password_hash(password: str) -> str:
    """Hash a password."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def create_user(
    username: str,
    email: str,
    password: str,
    full_name: Optional[str] = None,
    role: str = "analyst",
) -> UserInDB:
    """Create a new user."""
    if username in _users_db:
        raise ValueError(f"User {username} already exists")
    
    user = UserInDB(
        id=secrets.token_urlsafe(16),
        username=username,
        email=email,
        hashed_password=get_password_hash(password),
        full_name=full_name,
        role=role,
        is_active=True,
        created_at=datetime.utcnow(),
        last_login=None,
    )
    _users_db[username] = user
    return user


def get_user(username: str) -> Optional[UserInDB]:
    """Get user by username."""
    return _users_db.get(username)


def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    """Authenticate a user."""
    user = get_user(username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    if not user.is_active:
        return None
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_token(token: str) -> Optional[dict]:
    """Decode and validate a JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


def get_current_user(token: str) -> Optional[UserInDB]:
    """Get current user from token."""
    payload = decode_token(token)
    if not payload:
        return None
    username = payload.get("sub")
    if not username:
        return None
    user = get_user(username)
    return user


def check_permission(user: UserInDB, permission: str) -> bool:
    """Check if user has a specific permission."""
    if user.role == "admin":
        return True
    permissions = ROLE_PERMISSIONS.get(user.role, [])
    return permission in permissions or "*" in permissions


def require_permission(permission: str):
    """Dependency to require a specific permission."""
    from fastapi import Depends, HTTPException, status
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    
    security = HTTPBearer()
    
    def _check(credentials: HTTPAuthorizationCredentials = Depends(security)) -> UserInDB:
        user = get_current_user(credentials.credentials)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not check_permission(user, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission} required",
            )
        return user
    
    return _check


def init_default_users():
    """Initialize default users from environment or create defaults."""
    # Create admin user if not exists
    admin_user = os.getenv("ERREETOOL_API_ADMIN_USER", "admin")
    admin_pass = os.getenv("ERREETOOL_API_ADMIN_PASS", "admin123")
    admin_email = os.getenv("ERREETOOL_API_ADMIN_EMAIL", "admin@localhost")
    
    if not get_user(admin_user):
        create_user(admin_user, admin_email, admin_pass, "Administrator", "admin")
        print(f"Created default admin user: {admin_user}")


# Initialize default users on import
init_default_users()