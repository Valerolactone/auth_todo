from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from app.models.database import database
from app.routers import users


@asynccontextmanager
async def lifespan(app: FastAPI):
    await database.connect()
    yield
    await database.disconnect()


app = FastAPI(lifespan=lifespan)


@app.get("/")
def get_home():
    return {"data": "Hello world"}


app.include_router(users.router)
