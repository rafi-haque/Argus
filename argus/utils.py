"""Logging and error handling utilities."""
import logging
import sys
from typing import Optional


def setup_logging(verbose: bool = False, log_file: Optional[str] = None):
    """Setup logging configuration.
    
    Args:
        verbose: Enable verbose logging
        log_file: Optional log file path
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    
    # Create formatters
    console_formatter = logging.Formatter(
        '%(levelname)s: %(message)s'
    )
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Setup root logger
    logger = logging.getLogger('argus')
    logger.setLevel(log_level)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """Get logger for module.
    
    Args:
        name: Logger name
    
    Returns:
        logging.Logger: Logger instance
    """
    return logging.getLogger(f'argus.{name}')


class ArgusException(Exception):
    """Base exception for Argus scanner."""
    pass


class ConfigurationError(ArgusException):
    """Configuration error."""
    pass


class ScanningError(ArgusException):
    """Scanning error."""
    pass


class CrawlingError(ArgusException):
    """Crawling error."""
    pass
