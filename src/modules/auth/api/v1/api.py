from datetime import datetime

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from google.auth.transport import requests
from google.oauth2 import id_token
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
    create_user,
    decode_jwt_token,
    get_hashed_password,
    is_user_exist,
    store_user_token,
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
    new_user = create_user(
        db,
        {
            "email": user.email,
            "encrypted_password": encrypted_password,
        },
    )
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
    store_user_token(
        db,
        {
            "user_id": user.id,
            "access_token": access_token,
            "refresh_token": refresh_token,
        },
    )

    response.set_cookie(
        key="access_token",
        value=access_token,
        # httponly=True,
        # secure=False,
        samesite="none",
        max_age=3600,
        # domain="localhost",
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        # httponly=True,
        # secure=False,
        samesite="none",
        max_age=3600,
        # domain="localhost",
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
    }


@router.post("/auth/google")
# pylint: disable=too-many-try-statements
async def authenticate_google_user(
    token: user_schema.GoogleLogin,
    response: Response,
    db: Session = Depends(get_session),
):
    try:
        user_info = id_token.verify_oauth2_token(
            token.id_token, requests.Request(), settings.GOOGLE_CLIENT_ID
        )
        user_email = user_info.get("email")

        if not user_email.endswith("coloredcow.in"):
            raise HTTPException(status_code=403, detail="Unauthorized domain")

        user: [bool, User] = is_user_exist(db, user_email)
        if user is False:
            user = create_user(
                db,
                {
                    "email": user_email,
                    "provider": "google",
                },
            )

        auth_cookie = jwt.encode(
            {"email": user_email},
            settings.SECRET_KEY,
            algorithm=settings.TOKEN_GENERATION_ALGORITHM,
        )
        store_user_token(
            db, {"user_id": user.id, "access_token": auth_cookie, "refresh_token": None}
        )
        response.set_cookie(
            key="auth_cookie",
            value=auth_cookie,
            # samesite="none",
            max_age=3600,
        )
        return {"status": "success", "auth_cookie": auth_cookie}
    except ValueError as e:
        return {"status": "error", "message": str(e)}


# pylint: enable=too-many-try-statements


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


@router.post("/verify-token")
# pylint: disable=unused-argument
def verify_token(request=Depends(OAuth2PasswordBearerWithCookie())):
    return {"message": "User authenticated successfully"}


# pylint: enable=unused-argument
