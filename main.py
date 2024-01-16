import os

from dotenv import load_dotenv
from fastapi import FastAPI

from app.api import demo
from app.logging.utils import initLogging

load_dotenv()
app = FastAPI()
app_logger = initLogging()

DATABASE_URL = f"""postgresql://{os.getenv('POSTGRES_USER')}:{os.getenv('POSTGRES_PASSWORD')}
@db:5432/{os.getenv('POSTGRES_DB')}"""

app.include_router(demo.router)
