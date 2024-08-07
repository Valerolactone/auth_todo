import os
from datetime import datetime, timedelta
from typing import Optional

from jose import jwt


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=int(os.getenv("ACCESS_TOKEN_EXPIRATION_TIME"))
        )
    to_encode.update({"exp": expire})
    return jwt.encode(
        to_encode, os.getenv("JWT_SECRET_KEY"), algorithm=os.getenv("JWT_ALGORITHM")
    )


def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(
        days=int(os.getenv("REFRESH_TOKEN_EXPIRATION_TIME"))
    )
    to_encode.update({"exp": expire})
    return jwt.encode(
        to_encode, os.getenv("JWT_SECRET_KEY"), algorithm=os.getenv("JWT_ALGORITHM")
    )
