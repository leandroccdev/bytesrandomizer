from typing import Any, Callable, Iterator, List, Tuple, Union
from time import perf_counter

def format_bytes(size: Union[int, float]) -> str:
    '''Show an amount bytes in human form.

    Args:
        size (Union[int, float]): The amount of bytes to format.

    Returns: The human amount and it unit.
    '''
    for u in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.1f} {u}"
        size /= 1024.0
    return f"{size:.1f} PB"

def get_execution_time(func) -> Callable:
    '''Determines and retrieves the execution time of a function.

    Returns: Callable wrapper function.
    '''
    def wrapper(*args, **kwargs) -> Tuple[Any, float]:
        start = perf_counter()
        result: Any = func(*args, **kwargs)
        end = perf_counter()

        return result, end - start

    return wrapper

def print_execution_time(func) -> Callable:
    '''Determines the execution time of a function.

    The execution time is printed at stdout.

    Returns: Callable wrapper function.
    '''
    def wrapper(*args, **kwargs) -> Any:
        start = perf_counter()
        result: Any = func(*args, **kwargs)
        end = perf_counter()
        print(f"Execution time: {end - start:5f}s")

        return result

    return wrapper

class ListEndlessIterator:
    '''Enable endless iteration over a list.

    Meaning that never raises StopIteration. When end of sequence is reached
    the internal counter is reseted to zero to start over again.
    '''

    def __init__(self, l: List) -> None:
        '''Initialize the iterator instance.

        Args:
            l (list): The sequence to be iterate over.
        '''
        self._i = 0
        self._list: List = l

    def __iter__(self) -> Iterator[Any]:
        return self

    def __next__(self) -> Any:
        '''Never raises StopIteration.'''
        # Resets the internal counter
        if self._i >= len(self._list):
            self._i = 0

        if self._i < len(self._list):
            item: Any = self._list[self._i]
            self._i += 1
            return item