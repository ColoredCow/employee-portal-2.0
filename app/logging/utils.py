import logging
import os
from logging.handlers import TimedRotatingFileHandler


def initLogging():
    log_file_path = os.getenv("APP_LOG_FILE_PATH")
    log_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    log_handler = TimedRotatingFileHandler(
        filename=log_file_path,
        when="midnight",
        interval=1,
        backupCount=7,  # Keep 7 days of logs
    )
    log_handler.setFormatter(log_formatter)
    logging.basicConfig(level=logging.INFO, handlers=[log_handler])

    return logging.getLogger()
