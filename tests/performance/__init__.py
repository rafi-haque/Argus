"""Performance test configuration and utilities."""
import time
import functools
from typing import Callable


def measure_time(func: Callable) -> Callable:
    """Decorator to measure function execution time.
    
    Args:
        func: Function to measure
    
    Returns:
        Wrapped function with timing
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        elapsed = time.time() - start_time
        print(f"{func.__name__} took {elapsed:.2f} seconds")
        return result
    return wrapper


def assert_performance(max_duration: float):
    """Decorator to assert function completes within time limit.
    
    Args:
        max_duration: Maximum allowed duration in seconds
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            result = func(*args, **kwargs)
            elapsed = time.time() - start_time
            
            assert elapsed < max_duration, (
                f"{func.__name__} took {elapsed:.2f}s, "
                f"expected <{max_duration}s"
            )
            return result
        return wrapper
    return decorator
