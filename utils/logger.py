#!/usr/bin/env python3
"""
Logger Module

Centralized logging configuration for the AI Code Reviewer.
"""

import logging
import sys
from typing import Optional

def setup_logger(
    name: str = "ai_code_reviewer",
    level: int = logging.INFO,
    verbose: bool = False,
    log_file: Optional[str] = None
) -> logging.Logger:
    """
    Setup and configure a logger.
    
    Args:
        name: Logger name
        level: Logging level (default: INFO)
        verbose: If True, set level to DEBUG and add more details
        log_file: Optional file path to log to
        
    Returns:
        Configured logger instance
    """
    # Create logger
    logger = logging.getLogger(name)
    
    # Avoid adding handlers multiple times
    if logger.handlers:
        return logger
    
    # Set level
    if verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(level)
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
    )
    simple_formatter = logging.Formatter(
        '%(levelname)s: %(message)s'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    if verbose:
        console_handler.setFormatter(detailed_formatter)
        console_handler.setLevel(logging.DEBUG)
    else:
        console_handler.setFormatter(simple_formatter)
        console_handler.setLevel(level)
    
    logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(detailed_formatter)
            file_handler.setLevel(logging.DEBUG)
            logger.addHandler(file_handler)
            logger.info(f"Logging to file: {log_file}")
        except Exception as e:
            logger.warning(f"Could not set up file logging to {log_file}: {e}")
    
    return logger

def get_logger(name: str = "ai_code_reviewer") -> logging.Logger:
    """
    Get or create a logger with the given name.
    
    Args:
        name: Logger name
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)

# Example usage
if __name__ == "__main__":
    # Test the logger
    logger = setup_logger(verbose=True)
    
    logger.debug("Debug message")
    logger.info("Info message")
    logger.warning("Warning message")
    logger.error("Error message")
    
    # Test with file logging
    file_logger = setup_logger(name="file_logger", log_file="test.log", verbose=False)
    file_logger.info("This should go to both console and file")
