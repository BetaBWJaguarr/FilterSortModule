import logging
import time
import traceback


# Custom Formatter for Detailed Logging
class CustomFormatter(logging.Formatter):
    def formatException(self, exc_info):
        result = super().formatException(exc_info)
        return f"{result}\n{'-'*60}"


# Configure Logging
def setup_logging(log_file="operations.log", level=logging.ERROR):
    logger = logging.getLogger()
    handler = logging.FileHandler(log_file)
    formatter = CustomFormatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(level)
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