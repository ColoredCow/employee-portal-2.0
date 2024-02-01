from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.security import OAuth2
from sqlalchemy.orm import Session

from src.database.session import get_session
from src.modules.auth.utils.utils import verify_google_token, verify_jwt_token


class OAuth2PasswordBearerWithCookie(OAuth2):
    def __init__(
        self,
        tokenUrl: Optional[str] = "/login",
        scheme_name: Optional[str] = None,
        scopes: Optional[dict[str, str]] = None,
        auto_error: bool = True,
    ):
        if not scopes:
            scopes = {}
        flows = OAuthFlowsModel(password={"tokenUrl": tokenUrl, "scopes": scopes})
        super().__init__(flows=flows, scheme_name=scheme_name, auto_error=auto_error)

    async def __call__(
        self, request: Request, db: Session = Depends(get_session)
    ) -> Optional[str]:
        access_token: str = request.cookies.get("access_token")
        auth_token: str = request.cookies.get("auth_cookie")
        authorization: bool = False
        print(request.cookies)
        if auth_token:
            authorization: bool = verify_google_token(db, auth_token)

        if access_token and not authorization:
            authorization: bool = verify_jwt_token(db, access_token, "access_token")

        if not authorization:
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return None
