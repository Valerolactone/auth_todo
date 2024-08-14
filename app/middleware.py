import os

from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware


class CatchAllMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        if response.status_code == 404:
            token = request.headers.get("Authorization")

            if not token:
                return JSONResponse(
                    status_code=401, content={"error": "Token is required."}
                )

            redirect_url = f"{os.getenv("DRF_URL")}{request.url.path}"
            response = RedirectResponse(url=redirect_url)
            response.headers["Authorization"] = token

        return response
