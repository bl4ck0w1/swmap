import logging
import logging.handlers
import sys
from typing import Optional, Dict, Any
from pathlib import Path
import time  


class LogFormatter(logging.Formatter):
    COLORS = {
        "DEBUG": "\033[36m", 
        "INFO": "\033[32m",  
        "WARNING": "\033[33m",  
        "ERROR": "\033[31m", 
        "CRITICAL": "\033[41m",  
        "RESET": "\033[0m", 
    }

    def __init__(self, use_colors: bool = True):
        super().__init__()
        self.use_colors = use_colors and sys.stderr.isatty()

    def format(self, record: logging.LogRecord) -> str:
        if record.levelno >= logging.ERROR:
            fmt = "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"
        elif record.levelno >= logging.WARNING:
            fmt = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        else:
            fmt = "%(asctime)s - %(levelname)s - %(message)s"

        base = logging.Formatter(fmt, datefmt="%Y-%m-%d %H:%M:%S")

        original_levelname = record.levelname
        original_msg = record.msg

        try:
            if self.use_colors and original_levelname in self.COLORS:
                color = self.COLORS[original_levelname]
                reset = self.COLORS["RESET"]
                record.levelname = f"{color}{original_levelname}{reset}"
                record.msg = f"{color}{original_msg}{reset}"
            return base.format(record)
        finally:
            record.levelname = original_levelname
            record.msg = original_msg

def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    max_bytes: int = 10 * 1024 * 1024,  
    backup_count: int = 5,
    enable_console: bool = True,
) -> logging.Logger:

    log_level = getattr(logging, level.upper(), logging.INFO)
    logger = logging.getLogger("swmap")
    logger.setLevel(log_level)

    for h in list(logger.handlers):
        logger.removeHandler(h)

    handlers = []

    if enable_console:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(LogFormatter())
        handlers.append(console_handler)

    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(LogFormatter(use_colors=False))
        handlers.append(file_handler)

    for h in handlers:
        logger.addHandler(h)

    logger.propagate = False
    return logger


def get_logger(name: Optional[str] = None) -> logging.Logger:
    return logging.getLogger(f"swmap.{name}" if name else "swmap")


class PerformanceLogger:
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or get_logger("performance")
        self.timers: Dict[str, Dict[str, Any]] = {}

    def start_timer(self, operation: str):
        self.timers[operation] = {"start": time.time(), "end": None, "duration": None}
        self.logger.debug(f"Started: {operation}")

    def stop_timer(self, operation: str) -> float:
        t = self.timers.get(operation)
        if not t:
            self.logger.warning(f"No timer found for operation: {operation}")
            return 0.0
        t["end"] = time.time()
        t["duration"] = (t["end"] - t["start"]) if t["start"] else 0.0
        self.logger.debug(f"Completed: {operation} in {t['duration']:.3f}s")
        return float(t["duration"])

    def log_operation(self, operation: str, details: Optional[Dict[str, Any]] = None):
        duration = self.stop_timer(operation)
        payload = {
            "operation": operation,
            "duration_seconds": round(duration, 3),
            "timestamp": time.time(),
        }
        if details:
            payload.update(details)
        self.logger.info(f"Performance - {operation}: {duration:.3f}s", extra=payload)

default_logger = setup_logging()
