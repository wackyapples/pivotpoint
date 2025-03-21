import logging
import sys
import time
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, TextIO


class Level(IntEnum):
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARN = logging.WARNING
    ERROR = logging.ERROR

    def __str__(self) -> str:
        return self.name.lower()

    @staticmethod
    def from_string(level_str: str) -> "Level":
        """Convert a string level to Level enum."""
        level_map = {
            "debug": Level.DEBUG,
            "info": Level.INFO,
            "warn": Level.WARN,
            "warning": Level.WARN,
            "error": Level.ERROR,
        }
        return level_map.get(level_str.lower(), Level.INFO)


@dataclass
class Attr:
    """Represents a key-value attribute pair."""

    key: str
    value: Any

    def __str__(self) -> str:
        if isinstance(self.value, str):
            return f'{self.key}="{self.value}"'
        return f"{self.key}={self.value}"


class Record:
    """Represents a log record with structured data."""

    def __init__(self, time: float, level: Level, msg: str, attrs: list[Attr] = None):
        self.time = time
        self.level = level
        self.msg = msg
        self.attrs = attrs or []

    def add(self, key: str, value: Any) -> None:
        """Add a new attribute to the record."""
        self.attrs.append(Attr(key, value))


class Handler:
    """Base handler class for processing log records."""

    def __init__(
        self,
        output: TextIO = sys.stdout,
        level: Level = Level.INFO,
        add_source: bool = False,
    ):
        self.output = output
        self.level = level
        self.add_source = add_source

    def enabled(self, level: Level) -> bool:
        """Check if a given log level is enabled."""
        return level >= self.level

    def handle(self, record: Record) -> None:
        """Process a log record."""
        raise NotImplementedError


class TextHandler(Handler):
    """Formats log records as human-readable text."""

    def handle(self, record: Record) -> None:
        if not self.enabled(record.level):
            return

        # Format time as RFC3339 with milliseconds
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%S.", time.localtime(record.time))
        timestamp += f"{(record.time % 1):0.3f}"[2:] + "Z"

        # Build the log line
        parts = [f"time={timestamp}", f"level={record.level}", f'msg="{record.msg}"']

        # Add all attributes
        for attr in record.attrs:
            parts.append(str(attr))

        # Write the log line
        print(" ".join(parts), file=self.output, flush=True)


class JSONHandler(Handler):
    """Formats log records as JSON."""

    def handle(self, record: Record) -> None:
        if not self.enabled(record.level):
            return

        import json

        # Create the base record
        output = {
            "time": time.strftime("%Y-%m-%dT%H:%M:%S.", time.localtime(record.time))
            + f"{(record.time % 1):0.3f}"[2:]
            + "Z",
            "level": str(record.level),
            "msg": record.msg,
        }

        # Add all attributes
        for attr in record.attrs:
            output[attr.key] = attr.value

        # Write the JSON log line
        print(json.dumps(output), file=self.output, flush=True)


class Logger:
    """Main logger class that processes log records."""

    def __init__(self, handler: Handler):
        self.handler = handler

    def _log(self, level: Level, msg: str, *args: Any, **kwargs: Any) -> None:
        if not self.handler.enabled(level):
            return

        # Create the record
        record = Record(time.time(), level, msg)

        # Add positional args as attr1, attr2, etc.
        for i, arg in enumerate(args, 1):
            if isinstance(arg, Attr):
                record.attrs.append(arg)
            else:
                record.add(f"attr{i}", arg)

        # Add keyword args
        for key, value in kwargs.items():
            record.add(key, value)

        # Handle the record
        self.handler.handle(record)

    def debug(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._log(Level.DEBUG, msg, *args, **kwargs)

    def info(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._log(Level.INFO, msg, *args, **kwargs)

    def warn(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._log(Level.WARN, msg, *args, **kwargs)

    def error(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._log(Level.ERROR, msg, *args, **kwargs)


# Helper functions to create attributes
def string(key: str, value: str) -> Attr:
    return Attr(key, value)


def int64(key: str, value: int) -> Attr:
    return Attr(key, value)


def float64(key: str, value: float) -> Attr:
    return Attr(key, value)


def bool_(key: str, value: bool) -> Attr:
    return Attr(key, value)


def any_(key: str, value: Any) -> Attr:
    return Attr(key, value)


# Default logger
_default_logger = Logger(TextHandler())


# Public interface
def get_logger() -> Logger:
    return _default_logger


def set_default(logger: Logger) -> None:
    global _default_logger
    _default_logger = logger


def debug(msg: str, *args: Any, **kwargs: Any) -> None:
    _default_logger.debug(msg, *args, **kwargs)


def info(msg: str, *args: Any, **kwargs: Any) -> None:
    _default_logger.info(msg, *args, **kwargs)


def warn(msg: str, *args: Any, **kwargs: Any) -> None:
    _default_logger.warn(msg, *args, **kwargs)


def error(msg: str, *args: Any, **kwargs: Any) -> None:
    _default_logger.error(msg, *args, **kwargs)
