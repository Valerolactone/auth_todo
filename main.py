import uvicorn
from dotenv import load_dotenv
from fastapi import APIRouter, FastAPI
from middleware import CatchAllMiddleware

from app.routers import login_router, user_router

load_dotenv()

app = FastAPI(title='TODO-Auth')


@app.get("/")
def health_check():
    return {"data": "Hello world"}


app.add_middleware(CatchAllMiddleware)

main_api_router = APIRouter()
main_api_router.include_router(user_router, prefix="/users", tags=["users"])
main_api_router.include_router(login_router, prefix="/login", tags=["login"])

app.include_router(main_api_router)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
