from sqlalchemy import select
from fastapi import APIRouter, Depends
from databases import Database
from app.models import users

from app.schemas.users import UserList
from models.database import database

router = APIRouter()


@router.get("/users", response_model=UserList)
async def get_users(db: Database = Depends(lambda: database)):
    query = select(users.users)
    all_users = await db.fetch_all(query)
    return {"users": all_users}
