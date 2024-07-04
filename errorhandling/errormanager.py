import traceback

class CustomValueError(ValueError):
    def __init__(self, message="There is a value error", details=None):
        self.message = message
        self.details = details
        self.traceback = traceback.format_exc()
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}\nDetails: {self.details}\nTraceback: {self.traceback}"

class CustomTypeError(TypeError):
    def __init__(self, message="There is a type error", details=None):
        self.message = message
        self.details = details
        self.traceback = traceback.format_exc()
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}\nDetails: {self.details}\nTraceback: {self.traceback}"

class CustomIndexError(IndexError):
    def __init__(self, message="There is an index error", details=None):
        self.message = message
        self.details = details
        self.traceback = traceback.format_exc()
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}\nDetails: {self.details}\nTraceback: {self.traceback}"

class CustomKeyError(KeyError):
    def __init__(self, message="There is a key error", details=None):
        self.message = message
        self.details = details
        self.traceback = traceback.format_exc()
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}\nDetails: {self.details}\nTraceback: {self.traceback}"

class CustomFileNotFoundError(FileNotFoundError):
    def __init__(self, message="File not found", details=None):
        self.message = message
        self.details = details
        self.traceback = traceback.format_exc()
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}\nDetails: {self.details}\nTraceback: {self.traceback}"
