import logging
import sys
import time
import traceback
from datetime import datetime
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler


# Custom Formatter for Detailed Logging
class CustomFormatter(logging.Formatter):
    def formatException(self, exc_info):
        result = super().formatException(exc_info)
        return f"{result}\n{'-'*60}"

# Configure Logging
def setup_logging(
        log_file="operations.log",
        level="ERROR",
        console_output=False,
        max_bytes=10**6,  # 1 MB
        backup_count=5,
        rotation_type="size",
        log_format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        log_format_exception="%(asctime)s - %(name)s - %(levelname)s - %(message)s - %(exc_info)s"
):
    logger = logging.getLogger()


    level = level.upper()
    if hasattr(logging, level):
        logger.setLevel(getattr(logging, level))
    else:
        raise ValueError("Invalid log level. Use 'DEBUG', 'INFO', 'WARNING', 'ERROR', or 'CRITICAL'.")

    formatter = CustomFormatter(log_format)
    formatter_exception = CustomFormatter(log_format_exception)

    if rotation_type == "time":
        log_file = f"operations_{datetime.now().strftime('%Y%m%d')}.log"

    if rotation_type == "size":
        handler = RotatingFileHandler(
            log_file, maxBytes=max_bytes, backupCount=backup_count
        )
    elif rotation_type == "time":
        handler = TimedRotatingFileHandler(
            log_file, when="midnight", interval=1, backupCount=backup_count
        )
    else:
        raise ValueError("Invalid rotation_type. Use 'size' or 'time'.")

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    return logger


# Custom Error Base Class
class CustomError(Exception):
    def __init__(self, message, details=None, error_code=None):
        self.message = message
        self.details = details or "No additional details provided."
        self.error_code = error_code or "N/A"
        self.traceback = traceback.format_exc()
        self.timestamp = time.ctime()
        super().__init__(self.message)
        self.log_error()

    def __str__(self):
        return (
            f"Error: {self.message}\n"
            f"Error Code: {self.error_code}\n"
            f"Details: {self.details}\n"
            f"Timestamp: {self.timestamp}\n"
            f"Traceback:\n{self.traceback}"
        )

    def log_error(self):
        logging.error(f"{type(self).__name__} occurred: {self}")

    def log_error(self):
        logger = logging.getLogger(__name__)
        logger.error(f"{type(self).__name__} occurred: {self}", exc_info=True)


# Custom Exceptions with Detailed Messages and Error Codes
class CustomValueError(CustomError, ValueError):
    def __init__(self, message="A value error occurred", details=None, error_code=1001):
        super().__init__(message, details, error_code)


class CustomTypeError(CustomError, TypeError):
    def __init__(self, message="A type error occurred", details=None, error_code=1002):
        super().__init__(message, details, error_code)


class CustomIndexError(CustomError, IndexError):
    def __init__(self, message="An index error occurred", details=None, error_code=1003):
        super().__init__(message, details, error_code)


class CustomKeyError(CustomError, KeyError):
    def __init__(self, message="A key error occurred", details=None, error_code=1004):
        super().__init__(message, details, error_code)


class CustomFileNotFoundError(CustomError, FileNotFoundError):
    def __init__(self, message="File not found", details=None, error_code=1005):
        super().__init__(message, details, error_code)