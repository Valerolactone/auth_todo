import os
from datetime import datetime, timedelta
from typing import Optional

import jwt
from fastapi import Depends, HTTPException
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from db.dals import TokenDAL
from db.models import RefreshToken
from db.session import get_db


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
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


def create_refresh_token(data: dict) -> dict:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(
        days=int(os.getenv("REFRESH_TOKEN_EXPIRATION_TIME"))
    )
    to_encode.update({"exp": expire})
    token = jwt.encode(
        to_encode, os.getenv("JWT_SECRET_KEY"), algorithm=os.getenv("JWT_ALGORITHM")
    )
    return {"refresh_token": token, "expires_at": expire}


async def add_refresh_token_to_db(
    data: dict, db: AsyncSession = Depends(get_db)
) -> str:
    refresh_token_data = create_refresh_token(data)
    refresh_token = refresh_token_data["refresh_token"]
    expires_at = refresh_token_data["expires_at"]
    db_refresh_token = RefreshToken(
        user_pk=data["user_pk"], token=refresh_token, expires_at=expires_at
    )
    try:
        db.add(db_refresh_token)
        await db.flush()
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

    return refresh_token


async def update_refresh_token_in_db(
    data: dict, db: AsyncSession = Depends(get_db)
) -> str:
    refresh_token_data = create_refresh_token(data)
    refresh_token = refresh_token_data["refresh_token"]
    expires_at = refresh_token_data["expires_at"]
    token_dal = TokenDAL(db)
    try:
        db_refresh_token = await token_dal.get_user_refresh_token(data["user_pk"])
        if db_refresh_token is None:
            raise HTTPException(status_code=404, detail="Refresh token not found")

        db_refresh_token.token = refresh_token
        db_refresh_token.expires_at = expires_at

        await db.flush()
        await db.refresh(db_refresh_token)
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

    return refresh_token
