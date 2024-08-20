import os
import re

import httpx
import uvicorn
from dotenv import load_dotenv
from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse

from app.routers import login_router, user_router

load_dotenv()

app = FastAPI(title='TODO-Auth')

REDIRECT_MAP = {
    r'^/core/(.*)$': f'{os.getenv("DRF_URL")}',
}


@app.middleware("http")
async def regex_redirect_middleware(request: Request, call_next):
    for pattern, target_url in REDIRECT_MAP.items():
        match = re.match(pattern, request.url.path)
        if not match:
            continue

        auth_header = (
            {"Authorization": request.headers["Authorization"]}
            if "Authorization" in request.headers
            else {}
        )
        new_url = f"{target_url}/{match.group(1)}"

        request_data = (
            request.query_params if request.method in ["GET", "DELETE"] else None
        )
        json_data = await request.json() if request.method in ["POST", "PUT"] else None

        async with httpx.AsyncClient() as client:
            response = await client.request(
                request.method,
                new_url,
                headers=auth_header,
                json=json_data,
                params=request_data,
            )

        return JSONResponse(content=response.json(), status_code=response.status_code)

    response = await call_next(request)
    return response


@app.get("/")
def health_check():
    return {"data": "Hello world"}


main_api_router = APIRouter()
main_api_router.include_router(user_router, prefix="/users", tags=["users"])
main_api_router.include_router(login_router, prefix="/login", tags=["login"])

app.include_router(main_api_router)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
