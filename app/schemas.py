from datetime import datetime
from typing import Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, EmailStr


class TunedModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class UserIds(BaseModel):
    ids: List[int]


class UsersWithEmails(TunedModel):
    users: Dict[int, EmailStr]


class UserCreate(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    password: str


class UserOut(TunedModel):
    user_pk: int
    first_name: str
    last_name: str
    email: EmailStr
    role: str


class ExpandUserData(UserOut):
    role_id: int
    created_at: datetime
    deleted_at: Optional[datetime] = None
    is_active: bool
    is_verified: bool


class PaginatedResponse(TunedModel):
    users: List[Union[UserOut, ExpandUserData]]
    total: int
    page: int
    page_size: int
    total_pages: int
    has_next: bool
    has_prev: bool


class UserUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    password: Optional[str] = None


class AdminUserUpdate(BaseModel):
    role_name: Optional[str] = None
    is_active: Optional[bool] = None


class Token(BaseModel):
    access_token: str
    access_token_expires_at: datetime
    refresh_token: Optional[str] = None
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
