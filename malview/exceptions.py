"""Custom exceptions for malview."""


class MalviewError(Exception):
    """Base exception for all malview errors."""
    pass


class FileNotFoundError(MalviewError):
    """Raised when the specified file cannot be found."""
    pass


class InvalidPEFileError(MalviewError):
    """Raised when the file is not a valid PE file."""
    pass


class UnsupportedFileError(MalviewError):
    """Raised when the path is not something malview will read (e.g. a FIFO,
    device or directory, or a file over the size limit)."""
    pass
