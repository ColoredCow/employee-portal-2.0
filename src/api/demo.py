from fastapi import APIRouter

from src.logging.utils import initLogging

router = APIRouter()


@router.get("/")
async def pong():
    app_logger = initLogging()
    app_logger.info("Received request at root endpoint.")
    return {"message": "Hello World from FastAPI in Docker!"}
