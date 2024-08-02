from datetime import datetime
from typing import List

from pydantic import BaseModel, EmailStr


class TunedModel(BaseModel):
    class Config:
        from_attributes = True


class UserBase(TunedModel):
    user_pk: int
    first_name: str
    last_name: str
    email: EmailStr


class User(UserBase):
    created_at: datetime
    deleted_at: datetime
    is_active: bool


class UserList(BaseModel):
    users: List[UserBase]
