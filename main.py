import uvicorn
from fastapi import FastAPI, APIRouter
from app.routers import user_router

app = FastAPI(title='TODO-Auth')


@app.get("/")
def health_check():
    return {"data": "Hello world"}


main_api_router = APIRouter()
main_api_router.include_router(user_router, prefix="/users")

app.include_router(main_api_router)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
