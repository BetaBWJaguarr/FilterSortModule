class CustomValueError(ValueError):
    def __init__(self, message="There is a value error"):
        self.message = message
        super().__init__(self.message)

class CustomTypeError(TypeError):
    def __init__(self, message="There is a type error"):
        self.message = message
        super().__init__(self.message)

class CustomIndexError(IndexError):
    def __init__(self, message="There is an index error"):
        self.message = message
        super().__init__(self.message)

class CustomKeyError(KeyError):
    def __init__(self, message="There is a key error"):
        self.message = message
        super().__init__(self.message)

class CustomFileNotFoundError(FileNotFoundError):
    def __init__(self, message="File not found"):
        self.message = message
        super().__init__(self.message)