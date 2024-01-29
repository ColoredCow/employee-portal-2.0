from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Union

from jose import jwt
from jose.exceptions import JWTError
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from src.config import settings
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
