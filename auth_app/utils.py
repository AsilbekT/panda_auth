# auth_app/utils.py

from typing import Dict, Union
import jwt
import bcrypt
from datetime import datetime, timedelta
from fastapi import HTTPException
import redis

# Configure these with your Redis server details
SERVICES = {
    "userservice": "http://127.0.0.1:8001",
    "catalogservice": "https://catalogservice.inminternational.uz",
    "billingservice": "https://billingservice.inminternational.uz",
    "videoconversion": "http://127.0.0.1:8000"
}

REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_DB = 0

redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)

SECRET_KEY = "VpwI_yUDuQuhA1VEB0c0f9qki8JtLeFWh3lA5kKvyGnHxKrZ-M59cA"
ALGORITHM = "HS256"


def create_jwt_token(data: Dict[str, Union[str, int]]) -> str:
    """Create a JWT token with the given data."""
    expiration = datetime.utcnow() + timedelta(days=14)
    data["exp"] = expiration
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)


def verify_jwt_token(token: str) -> Dict[str, Union[str, int]]:
    """Decode and verify a JWT token."""
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    hashed_bytes = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_bytes.decode('utf-8')  # Return as string for easier storage


def verify_password(password: str, hashed_password: str) -> bool:
    """Verify a password against a hashed password."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


def invalidate_token(token: str) -> None:
    """Add a token to the blacklist in Redis."""
    # You can set an expiration for the token based on your JWT token's expiration
    # For example, setting it to 14 days (in seconds)
    expiration = 14 * 24 * 60 * 60

    redis_client.set(token, "blacklisted", ex=expiration)
