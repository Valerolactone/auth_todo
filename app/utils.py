from fastapi import Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from services import AuthenticationService
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import User
from db.session import get_db

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login/token")


async def get_refresh_token_from_headers(authorization: str = Header(None)):
    if authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer" and token:
            return token
    raise HTTPException(status_code=403, detail="Could not validate credentials")


async def get_auth_service(db: AsyncSession = Depends(get_db)):
    return AuthenticationService(db)


async def get_admin_user(
    token: str = Depends(oauth2_scheme),
    auth_service: AuthenticationService = Depends(get_auth_service),
) -> User:
    current_user = await auth_service.get_user_from_token(token)
    if current_user.role_id != 1:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have the necessary permissions",
        )
    return current_user
