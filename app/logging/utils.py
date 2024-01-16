import logging
import os


def initLogging():
    log_file_path = os.getenv("APP_LOG_FILE_PATH")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file_path),
            logging.StreamHandler(),  # Add this line if you also want to print logs to the console
        ],
    )

    return logging.getLogger()
