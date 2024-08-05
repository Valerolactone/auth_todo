from datetime import datetime
from typing import List, Dict

from pydantic import BaseModel, EmailStr


class TunedModel(BaseModel):
    class Config:
        from_attributes = True


class UserIds(TunedModel):
    ids: List[int]


class UserBase(TunedModel):
    user_pk: int
    first_name: str
    last_name: str
    email: EmailStr


class User(UserBase):
    created_at: datetime
    deleted_at: datetime
    is_active: bool
