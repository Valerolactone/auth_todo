from fastapi import Header, HTTPException


async def get_refresh_token_from_headers(authorization: str = Header(None)):
    if authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer" and token:
            return token
    raise HTTPException(status_code=403, detail="Could not validate credentials")
