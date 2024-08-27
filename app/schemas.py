from datetime import datetime
from typing import Dict, List, Optional

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
    role_id: int


class UserOut(TunedModel):
    user_pk: int
    first_name: str
    last_name: str
    email: EmailStr
    role_id: int


class ExpandUserData(UserOut):
    created_at: datetime
    deleted_at: datetime
    is_active: bool


class Token(BaseModel):
    access_token: str
    access_token_expires_at: datetime
    refresh_token: str
    token_type: str


class UserEmail(BaseModel):
    email: str


class ResetForgetPassword(BaseModel):
    new_password: str
    confirm_password: str


class PermissionCreate(BaseModel):
    name: str
    description: str


class PermissionUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None


class PermissionOut(TunedModel):
    permission_pk: int
    name: str
    description: str


class RoleCreate(BaseModel):
    name: str
    description: str


class RoleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None


class RoleOut(TunedModel):
    role_pk: int
    name: str
    description: str


class RolePermissionData(BaseModel):
    role: str
    permission: str


class RolePermissionOut(TunedModel):
    role_pk: int
    role: str
    permission_pk: int
    permission: str


class RoleWithPermissionOut(RoleOut):
    permissions: List[PermissionOut]


class PermissionWithRoleOut(PermissionOut):
    roles: List[RoleOut]
