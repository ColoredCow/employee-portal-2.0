from fastapi import FastAPI

from src.api import demo
from src.config import settings
from src.logging.utils import initLogging

app = FastAPI(title=settings.PROJECT_NAME, version=settings.PROJECT_VERSION)
app_logger = initLogging()

app.include_router(demo.router)
