from datetime import datetime

from pydantic import BaseModel, EmailStr


class UserBase(BaseModel):
    email: EmailStr
    password: str


class UserCreate(UserBase):
    pass


class UserLogin(BaseModel):
    username: EmailStr
    password: str


class GoogleLogin(BaseModel):
    id_token: str


class UserResponse(BaseModel):
    id: int
    email: EmailStr
    created_at: datetime


class RegistrationUserResponse(BaseModel):
    message: str
    data: UserResponse
