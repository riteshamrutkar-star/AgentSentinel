import logging
import sys

def get_audit_logger() -> logging.Logger:
    """Returns a dedicated logger for security audit trails."""
    logger = logging.getLogger("AgentSentinel.Audit")
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            fmt="%(asctime)s [AUDIT] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger

audit_logger = get_audit_logger()
