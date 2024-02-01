from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Optional, Union

from jose import jwt
from jose.exceptions import JWTError
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from src.config import settings
from src.modules.auth.models.user import User
from src.modules.auth.models.user_token import UserToken

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_hashed_password(password: str) -> str:
    return password_context.hash(password)


def verify_password(password: str, hashed_pass: str) -> bool:
    return password_context.verify(password, hashed_pass)


def create_access_token(subject: Union[str, Any], expires_delta: int = None) -> str:
    if expires_delta is not None:
        expires_delta = datetime.utcnow() + expires_delta

    else:
        expires_delta = datetime.utcnow() + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode = {"exp": expires_delta, "user_id": str(subject)}
    encoded_jwt = jwt.encode(
        to_encode, settings.SECRET_KEY, settings.TOKEN_GENERATION_ALGORITHM
    )

    return encoded_jwt


def create_refresh_token(subject: Union[str, Any], expires_delta: int = None) -> str:
    if expires_delta is not None:
        expires_delta = datetime.utcnow() + expires_delta
    else:
        expires_delta = datetime.utcnow() + timedelta(
            minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES
        )

    to_encode = {"exp": expires_delta, "user_id": str(subject)}
    encoded_jwt = jwt.encode(
        to_encode, settings.SECRET_KEY, settings.TOKEN_GENERATION_ALGORITHM
    )
    return encoded_jwt


def decode_jwt_token(jwt_token: str):
    try:
        # Decode and verify the token
        payload = jwt.decode(
            jwt_token, settings.SECRET_KEY, settings.TOKEN_GENERATION_ALGORITHM
        )
        return payload
    except JWTError:
        return None


def verify_jwt_token(db: Session, jwt_token: str, token_type: str) -> bool:
    isTokenValid: bool = False

    try:
        payload = decode_jwt_token(jwt_token)
    except:  # noqa: E722  # pylint: disable=W0702
        payload = None
    if payload:
        user_token = None
        if token_type == "access_token":
            user_token = (
                db.query(UserToken)
                .filter(
                    UserToken.user_id == payload.get("user_id"),
                    UserToken.access_token == jwt_token,
                )
                .first()
            )
        else:
            user_token = (
                db.query(UserToken)
                .filter(
                    UserToken.user_id == payload.get("user_id"),
                    UserToken.refresh_token == jwt_token,
                )
                .first()
            )

        if user_token is None:
            return isTokenValid

        isTokenValid = True
    return isTokenValid


def verify_google_token(db: Session, token: str) -> bool:
    isTokenValid: bool = False

    try:
        payload = decode_jwt_token(token)
    except:  # noqa: E722  # pylint: disable=W0702
        payload = None
    if payload:
        user_token = None
        user_email = payload.get("email")
        user = is_user_exist(db, user_email)

        if user is False:
            return isTokenValid

        user_token = (
            db.query(UserToken)
            .filter(
                UserToken.user_id == user.id,
                UserToken.access_token == token,
            )
            .first()
        )

        if user_token is None:
            return isTokenValid

        isTokenValid = True
    return isTokenValid


def is_user_exist(
    db: Session, user_email: Optional[str] = None, user_id: Optional[str] = None
):
    user = None

    if user_email:
        user = db.query(User).filter(User.email == user_email).first()
    if user_id:
        user = db.query(User).filter(User.id == user_id).first()

    if user is None:
        return False

    return user


def create_user(db: Session, user_data: dict):
    new_user = User(
        email=user_data["email"],
        password=user_data.get("encrypted_password", None),
        provider=user_data.get("provider", "normal"),
        is_verified=user_data.get("is_verified", True),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


def store_user_token(db: Session, token_data: dict):
    token_db = (
        db.query(UserToken)
        .filter(
            UserToken.user_id == token_data.get("user_id"),
            UserToken.access_token == token_data.get("access_token"),
        )
        .first()
    )

    if token_db is None:
        token_db = UserToken(
            user_id=token_data.get("user_id"),
            access_token=token_data.get("access_token"),
            refresh_token=token_data.get("refresh_token"),
            status=token_data.get("status", True),
        )
        db.add(token_db)
        db.commit()
        db.refresh(token_db)

    return token_db
