from datetime import datetime
from typing import Dict, List

from pydantic import BaseModel, EmailStr


class TunedModel(BaseModel):
    class Config:
        from_attributes = True


class UserIds(BaseModel):
    ids: List[int]


class UsersWithEmails(TunedModel):
    users: Dict[int, EmailStr]


class UserCreate(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    password: str


class UserData(TunedModel):
    user_pk: int
    first_name: str
    last_name: str
    email: EmailStr


class ExpandUserData(UserData):
    created_at: datetime
    deleted_at: datetime
    is_active: bool


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
