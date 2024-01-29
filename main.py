# pylint: disable=unused-import
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from src.api import demo
from src.config import settings
from src.database.base import Base  # noqa: F401
from src.database.session import get_session
from src.logging.utils import initLogging
from src.middlewares.custom import CustomMiddleware
from src.modules.auth.api.v1 import api

# pylint: enable=unused-import
app = FastAPI(title=settings.PROJECT_NAME, version=settings.PROJECT_VERSION)
db_session = get_session()
app_logger = initLogging()

origins = ["http://localhost:3000", "http://localhost:3000/*", "http://localhost:8000/"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(CustomMiddleware)
app.include_router(api.router)
app.include_router(demo.router)
