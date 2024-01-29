from datetime import datetime

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from jose import jwt
from sqlalchemy.orm import Session

from src.config import settings
from src.database.session import get_session
from src.modules.auth.auth_bearers.auth_bearer_with_cookie import (
    OAuth2PasswordBearerWithCookie,
)
from src.modules.auth.models.user import User
from src.modules.auth.models.user_token import UserToken
from src.modules.auth.schemas import user as user_schema
from src.modules.auth.schemas import user_token as token_schema
from src.modules.auth.utils.utils import (
    create_access_token,
    create_refresh_token,
    decode_jwt_token,
    get_hashed_password,
    verify_password,
)

router = APIRouter()


@router.post(
    "/register/",
    status_code=status.HTTP_201_CREATED,
    response_model=user_schema.RegistrationUserResponse,
)
def register_user(user: user_schema.UserCreate, db: Session = Depends(get_session)):
    existing_user = db.query(User).filter_by(email=user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    encrypted_password = get_hashed_password(user.password)

    new_user = User(email=user.email, password=encrypted_password, is_verified=True)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "message": "user created successfully",
        "data": {
            "id": new_user.id,
            "email": new_user.email,
            "created_at": new_user.created_at,
        },
    }


@router.post("/login", response_model=token_schema.TokenSchema)
def login(
    request: user_schema.UserLogin,
    response: Response,
    db: Session = Depends(get_session),
):
    user = db.query(User).filter(User.email == request.username).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )
    hashed_pass = user.password
    if not verify_password(request.password, hashed_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    access_token = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id)
    token_db = UserToken(
        user_id=user.id,
        access_token=access_token,
        refresh_token=refresh_token,
        status=True,
    )
    db.add(token_db)
    db.commit()
    db.refresh(token_db)

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=False,
        samesite="strict",
        max_age=3600,
        domain="localhost",
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False,
        samesite="strict",
        max_age=3600,
        domain="localhost",
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
    }


@router.post("/refresh-token", response_model=token_schema.RefreshTokenResponseSchema)
def regenerate_refresh_token(
    refresh_token: str = Cookie(None, description="Refresh token"),
    db: Session = Depends(get_session),
):
    token_data = decode_jwt_token(refresh_token)

    if not token_data:
        raise HTTPException(status_code=403, detail="Invalid token or expired token.")

    user_token = (
        db.query(UserToken)
        .filter(
            UserToken.user_id == token_data.get("user_id"),
            UserToken.refresh_token == refresh_token,
        )
        .first()
    )

    if user_token is None:
        raise HTTPException(status_code=403, detail="Invalid token or expired token.")

    new_access_token = create_access_token(token_data.get("user_id"))

    user_token.access_token = new_access_token
    db.commit()
    db.refresh(user_token)

    return {
        "access_token": new_access_token,
        "token_type": "Bearer",
    }


@router.get("/get-users")
# pylint: disable=unused-argument
def get_users(
    request=Depends(OAuth2PasswordBearerWithCookie()),
    db: Session = Depends(get_session),
):
    user = db.query(User).all()
    return user


# pylint: enable=unused-argument


@router.post("/change-password")
def change_password(
    request: token_schema.ChangePassword, db: Session = Depends(get_session)
):
    user = db.query(User).filter(User.email == request.email).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="User not found"
        )

    if not verify_password(request.old_password, user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid old password"
        )

    encrypted_password = get_hashed_password(request.new_password)
    user.password = encrypted_password
    db.commit()

    return {"message": "Password changed successfully"}


@router.post("/logout")
def logout(request: Request, db: Session = Depends(get_session)):
    token = request.access_token
    payload = jwt.decode(
        token, settings.SECRET_KEY, settings.TOKEN_GENERATION_ALGORITHM
    )
    user_id = payload["sub"]
    token_record = db.query(UserToken).all()
    info = []

    for record in token_record:
        if (datetime.utcnow() - record.created_at).days > 1:
            info.append(record.user_id)
    if info:
        db.query(UserToken).where(UserToken.user_id.in_(info)).delete()
        db.commit()

    db.query(UserToken).filter(
        UserToken.user_id == user_id, UserToken.access_token == token
    ).delete()
    db.commit()

    return {"message": "Logout Successfully"}
