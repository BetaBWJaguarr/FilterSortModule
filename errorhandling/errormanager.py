import logging
import time
import traceback


class CustomError(Exception):
    def __init__(self, message, details=None):
        self.message = message
        self.details = details
        self.traceback = traceback.format_exc()
        self.timestamp = time.ctime()
        super().__init__(self.message)
        self.log_error()

    def __str__(self):
        return f"{self.message}\nDetails: {self.details}\nTraceback: {self.traceback}\nTimestamp: {self.timestamp}"

    def log_error(self):
        logging.error(f"{type(self).__name__} occurred: {self}")

class CustomValueError(CustomError, ValueError):
    def __init__(self, message="There is a value error", details=None):
        super().__init__(message, details)

class CustomTypeError(CustomError, TypeError):
    def __init__(self, message="There is a type error", details=None):
        super().__init__(message, details)

class CustomIndexError(CustomError, IndexError):
    def __init__(self, message="There is an index error", details=None):
        super().__init__(message, details)

class CustomKeyError(CustomError, KeyError):
    def __init__(self, message="There is a key error", details=None):
        super().__init__(message, details)

class CustomFileNotFoundError(CustomError, FileNotFoundError):
    def __init__(self, message="File not found", details=None):
        super().__init__(message, details)
