from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from src.database.session import get_session
from src.modules.auth.utils.utils import verify_jwt_token


class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        print("FUNCTION CALLED")
        super().__init__(auto_error=auto_error)

    async def __call__(self, request: Request, db: Session = Depends(get_session)):
        credentials: HTTPAuthorizationCredentials = await super().__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(
                    status_code=403, detail="Invalid authentication scheme."
                )
            if not verify_jwt_token(db, credentials.credentials, "access_token"):
                raise HTTPException(
                    status_code=403, detail="Invalid token or expired token."
                )
            return credentials.credentials

        raise HTTPException(status_code=403, detail="Invalid authorization code.")


jwt_bearer = JWTBearer()
