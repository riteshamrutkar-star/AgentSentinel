import logging
import sys
from app.core.config import settings

def setup_logging() -> logging.Logger:
    """Configures application logging with a clean, standard format."""
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    logger = logging.getLogger(settings.APP_NAME)
    logger.setLevel(log_level)
    
    # Avoid duplicate handlers if setup_logging is called multiple times
    if not logger.handlers:
        logger.addHandler(handler)

    return logger

# Global logger instance
logger = setup_logging()
