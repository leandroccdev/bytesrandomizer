from .exceptions import *
from .util import ListEndlessIterator, format_bytes
from asyncio import create_task, gather, Task, to_thread
from concurrent.futures import Future, ThreadPoolExecutor
from functools import partial
from io import BytesIO
from secrets import SystemRandom
from typing import Dict, Iterator, List, Optional, NoReturn, Tuple
import logging

# Setup logger
logger = logging.getLogger(__name__)

class Log:
    '''Provides an internal logger instance.'''

    def __init__(self) -> None:
        '''Initialize the instance.'''
        global logger
        self._log: logging.Logger = logger.getChild(self.__class__.__name__)


class BinKeyApplier:
    '''Applies randomization key into a bytes sequences.'''

    def __init__(self, iterations: int = 1) -> None:
        '''Initialize the instance.

        key_a and key_b records are created automatically based on `iterations`.

        Args:
            iterations (int): Shuffle times to randomizes internal key records.
        '''
        # Creates key a record
        l: List[int] = list(range(256))
        for _ in range(iterations):
            SystemRandom().shuffle(l)
        self._key_a: Dict[int, int] = dict(enumerate(l))

        # Creates key b record
        self._key_b: List[int] = list(range(256))
        for _ in range(iterations):
            SystemRandom().shuffle(self._key_b)

    @property
    def key_a(self) -> bytes:
        '''The primary key record.'''
        return bytes(list(self._key_a.values()))

    @property
    def key_b(self) -> bytes:
        '''The auxiliary key record.'''
        return bytes(self._key_b)

    def apply(self, data: bytes) -> bytes:
        '''Randomizes the bytes sequence `data`.

        Args:
            data (bytes): the bytes sequence to be randomized.

        Returns: The randomized bytes sequence.
        '''
        r_data: List[int] = []
        for b in data:
            r_data.append(
                self._key_a[b ^ ListEndlessIterator(self._key_b).__next__()])
        return bytes(r_data)

    def apply_in_place(self, data: bytearray) -> None:
        '''In-place randomization of the bytearray `data`.

        Args:
            data (bytearray): the bytearray to be randomized.

        Returns: The randomized bytearray.
        '''
        for i in range(len(data)):
            data[i] = self._key_a \
                [data[i] ^ ListEndlessIterator(self._key_b).__next__()]


class BinKeyExtractor:
    '''Recovers the original bytes sequence from a randomized one.'''

    def __init__(self, key_a: bytes, key_b: bytes) -> None:
        '''Initialize the instance.

        Args:
            key_a (bytes): Key record a.
            key_b (bytes): Key record b.
        '''
        # Creates the 'key a' record for extraction
        self._key_a: Dict[int, int] = {}
        for i in range(len(key_a)):
            self._key_a[key_a[i]] = i

        # Creates the 'key b' record for extraction
        self._key_b = list(key_b)

    def extract(self, data: bytes) -> bytes:
        '''Recovers the original bytes sequence from a randomized one.

        Args:
            data (bytes): The randomized byte sequence used to recover the
            original one.

        Returns: The original bytes sequence.
        '''
        r_data: List[int] = []
        for b in data:
            r_data.append(
                self._key_a[b] ^ ListEndlessIterator(self._key_b).__next__())
        return bytes(r_data)

    def extract_in_place(self, data: bytearray) -> None:
        '''Recovers the original bytes sequence from a randomized one.

        This version modifies the `data` bytearray in-place, avoiding the
        creation of new bytearrays or byte sequences.

        Args:
            data (bytearray): The randomized bytearray used to recovers the
            original sequence.
        '''
        for i in range(len(data)):
            data[i] = self._key_a[data[i]] ^ \
                ListEndlessIterator(self._key_b).__next__()


class BinKeyExtractorFactory:
    '''Provides methods to create BinKeyExtractor instances.'''

    @staticmethod
    def new_from_hex_keys(key_a: str, key_b: str) -> BinKeyExtractor:
        '''Creates new instance of BinKey.

        Args:
            key_a (str): A record as hexadecimal string.
            key_b (str): B record as hexadecimal string.

        Returns: BinKey object instance.
        '''
        return BinKeyExtractor(
                key_a=bytes.fromhex(key_a),
                key_b=bytes.fromhex(key_b)
            )


class BinKeyApplierHandler:
    '''Randomizes a bytes sequence n times.'''

    def __init__(self, iterations: int = 1) -> None:
        '''Initialize the instance.

        Args:
            iterations (int): The number of iterations to apply distinct BinKeys.
        '''
        # Fix iterations
        if iterations <= 0:
            iterations = 1

        self._keys: List[BinKeyApplier] = [BinKeyApplier()
            for _ in range(iterations)]

    @property
    def keys(self) -> List[Tuple[bytes, bytes]]:
        '''BinKeyAppliers internal keys records.'''
        return [(k.key_a, k.key_b) for k in self._keys]

    def apply(self, data: bytes) -> bytes:
        '''Randomizes the bytes sequence `data` n times.

        Args:
            data (bytes): The bytes sequence to be randomized.

        Returns: The randomized bytes sequence.
        '''
        for bka in self._keys:
            data = bka.apply(data)
        return data

    def apply_in_place(self, data: bytearray) -> None:
        '''In-place randomization of a bytearray `data` n times.

        Args:
            data (bytearray): the baytearray to be randomized.
        '''
        for bka in self._keys:
            bka.apply_in_place(data)


class BinKeyExtractorHandler:
    '''Reccovers the original bytes sequence from a randomized one.'''

    def __init__(self, keys: List[BinKeyExtractor]) -> None:
        '''Initialize the instance.

        Args:
            keys (List[BinKeyExtractor]): A list of extractors to recover the
            original bytes sequence from the randomized one.
        '''
        if not keys:
            raise Exception("Empty 'keys' list was given!")

        self._keys: List[BinKeyExtractor] = keys

    def extract(self, data: bytes) -> bytes:
        '''Recovers the original bytes sequence from a randomized one.

        The application of n keys at `data` is automatically done by reversing
        the applicated keys.

        Args:
            data (bytes): The randomized byte sequence used to recover the
            original one.

        Returns: The original bytes sequence.
        '''
        for bke in reversed(self._keys):
            data = bke.extract(data)
        return data

    def extract_in_place(self, data: bytearray) -> None:
        '''Recovers the original bytes sequence from a randomized one.

        This version modifies the `data` bytearray in-place, avoiding the
        creation of new bytearrays or byte sequences.
        The application of n keys at `data` is automatically done by reversing
        the applicated keys.

        Args:
            data (bytearray): The randomized bytearray used to recovers the
            original sequence.
        '''
        for bke in reversed(self._keys):
            bke.extract_in_place(data)


class BinKeyHandler(Log):
    '''Randomizes a byte sequence n times.

    Also provides the capability to restore the byte sequence to its original
    state.
    '''

    def __init__(self, iterations: int = 1, **kwargs) -> None:
        '''Initializes the instance.

        Args:
            iterations (int): The number of iterations to apply distinct BinKeys.

        Kwargs:
            keys (List[Tuple(bytes, bytes)]): A list of pair of BinKey records
            a and b.
            When 'keys' is supplied, 'iterations' is ignored.

        Raises:
            Exception: When kwarg 'key' isn't an instance of list.
        '''
        Log.__init__(self)
        self._keys: List[BinKey] = []
        if "keys" in kwargs:
            keys = kwargs.get("keys")

            if not isinstance(keys, list):
                raise Exception("'keys' must be a list instance!")

            self._log.debug("Processing BinKey pairs records...")
            for ka, kb in keys:
                self._keys.append(BinKeyFactory.new_from_byte_keys(ka, kb))
        else:
            # Fix iterations
            if iterations <= 0:
                iterations = 1
                self._log.debug("'iterations' fixed to 1!")

            self._log.debug("Generating BinKeys...")
            self._keys += [BinKey() for _ in range(iterations)]

    @property
    def keys(self) -> List[Tuple[bytes, bytes]]:
        '''Used BinKeys.'''
        return [(k.key_a, k.key_b) for k in self._keys]

    def apply(self, data: bytes) -> bytes:
        '''Applies the generated BinKeys to data.

        Args:
            data (bytes): Bytes sequence to be randomized.

        Returns: The input bytes sequence once randomized.
        '''
        self._log.debug("Randomizing sequence...")
        for bk in self._keys:
            data = bk.apply(data)
        return data

    def reverse(self, data: bytes) -> bytes:
        '''Extracts the original bytes sequence from data using n BinKeys.

        Args:
            data (bytes): The randomized byte sequence used to recover
            the original one.

        Returns: The original bytes sequence after the reversing randomization.
        '''
        self._log.debug("Reversing randomized sequence...")
        for bk in reversed(self._keys):
            data = bk.reverse(data)
        return data


class Randomizer(Log):
    '''Randomizes a sequence of bytes using BinKeys.

    Attributes:
        - MAX_SIZE (int): The maximum size of the bytes sequence randomizer
        handles.
        - WORKERS (int): Number of worker for the ThreadPoolExecutor
    '''
    MAX_SIZE = 104857600 # 100 MB (in bytes).
    WORKERS = 10

    def __init__(self, block_size: Optional[int] = None, **kwargs) -> None:
        '''Initializes the instance.

        Args:
            block_size (Optional[int]): Amount of bytes to be randomized with
            same BinKey before generates new one.
            Ignored when: The value is None or is below 1.

        Raises:
            ExceedsMaximumSizeError: When data bytes sequence size is greater
            than Randomizer.MAX_SIZE. (The limit can be adjusted).
        '''
        Log.__init__(self)
        self._handlers: List[BinKeyHandler] = []
        # Flag: indicates when this instance requires a reset
        self.__is_reset_needed: bool = False

        # Ignores block_size
        if block_size is not None and block_size <= 0:
            self._log.debug(f"block_size is {block_size} not used!")
            block_size = None

        self._block_size: Optional[int] = block_size

    def __check_reset_needed(self) -> None:
        '''Check if this instance requires a reset.

        Raises:
            ResetRequiredError: When try to apply/reverse a sequence before
            resets the instance.
        '''
        if self.__is_reset_needed:
            raise ResetRequiredError("Reset is required!")

    def __new_handler(self, iterations: int = 1) -> BinKeyHandler:
        '''Adds new handler to internal list.

        Args:
            iterations (int): The number of iterations to apply distinct BinKeys.
        '''
        bkh: BinKeyHandler = BinKeyHandler(iterations)
        self._handlers.append(bkh)
        return bkh

    def __validate_max_data_size(self, data: bytes) -> Optional[NoReturn]:
        '''Validates the maximum data size allowed by Randomizer.MAX_SIZE.

        Args:
            data (bytes): The bytes sequence to be validated.
        Raises:
            - ExceedsMemoryError: When Randomizer.MAX_SIZE is exceeded.
        '''
        if len(data) > Randomizer.MAX_SIZE:
            max_size: str = format_bytes(Randomizer.MAX_SIZE)
            data_size: str = format_bytes(len(data))
            err: str = f"Data sequence is {data_size} length, " \
                + f"exceeds the maximum of {max_size}!"
            self._log.error(err)
            raise ExceedsMemoryError(err)

    @property
    def block_size(self) -> Optional[int]:
        '''Amount of bytes to be randomized with the same BinKey.

        Returns: None when is not used and a positive integer if does.
        '''
        return self._block_size

    @property
    def keys(self) -> List[List[Tuple[bytes, bytes]]]:
        '''List of handlers keys.'''
        return [h.keys for h in self._handlers]

    def apply(self, data: bytes, iterations=1) -> bytes:
        '''Randomizes a bytes sequence using a ThreadPool.

        The number of  ThreadPool workers is defined by `Randomizer.WORKERS`.

        Args:
            - data (bytes): The sequence of bytes to be randomized.
            - iterations (int): A positive integer. The number of iterations to
            apply distinct BinKeys. When the iterations number is lower or
            equals to zero, then is fixed to one.

        Returns: A randomized bytes sequence.
        '''
        self.__check_reset_needed()
        self.__validate_max_data_size(data)
        self.__is_reset_needed = True

        # Fix iterations to one
        if iterations <= 0:
            iterations = 1
            self._log.debug("'iterations' fixed to 1")

        randomized: bytes = b""

        # Process in blocks
        if self._block_size:
            executor: ThreadPoolExecutor = ThreadPoolExecutor(
                max_workers=Randomizer.WORKERS)
            tasks: List[Future] = []
            block_size: str = format_bytes(self._block_size)

            self._log.debug(
                f"Randomizing in blocks of {block_size}...")
            with BytesIO(data) as buffer, executor:
                while block := buffer.read(self._block_size):
                   bkh: BinKeyHandler = self.__new_handler(iterations)
                   tasks.append(executor.submit(bkh.apply, block))
                   self._log.debug("Task added...")

            # Collect results
            self._log.debug("Waiting for tasks completion...")
            randomized = b"".join([t.result() for t in tasks])

        # Process in a single block
        else:
            self._log.debug("Randomizing the entire sequence at once...")
            # Uses a single BinKey to randomize entire data sequence
            bkh: BinKeyHandler = self.__new_handler(iterations)
            randomized = bkh.apply(data)

        # Collect results
        return randomized

    async def apply_async(self, data: bytes, iterations=1) -> bytes:
        '''Randomizes a bytes sequence using in asynchronous mode.

        It must be called from a external event loop.
        Exmaple: `Asyncio.run(randomizer.apply_async(data))`

        Args:
            - data (bytes): The sequence of bytes to be randomized.
            - iterations (int): A positive integer. The number of iterations to
            apply distinct BinKeys. When the iterations number is lower or
            equals to zero, then is fixed to one.

        Returns: A randomized bytes sequence.
        '''
        self.__check_reset_needed()
        self.__validate_max_data_size(data)
        self.__is_reset_needed = True

        # Fix iterations to one
        if iterations <= 0:
            iterations = 1
            self._log.debug("'iterations' fixed to 1")

        randomized: bytes = b""

        # Process in blocks
        if self._block_size:
            tasks: List[Task] = []
            block_size: str = format_bytes(self._block_size)
            self._log.debug(
                f"Randomizing in blocks of {block_size}...")
            with BytesIO(data) as buffer:
                while block := buffer.read(self._block_size):
                    bkh: BinKeyHandler = self.__new_handler(iterations)
                    pt: partial = partial(bkh.apply, block)
                    tasks.append(create_task(to_thread(pt)))
                    self._log.debug("Task added...")

            # Collects and join blocks
            self._log.debug("Collecting and joining blocks...")
            randomized = b"".join(b for b in await gather(*tasks))

        # Process in a single block
        else:
            self._log.debug("Randomizing the entire sequence at once...")
            # Uses a single BinKey to randomize entire data sequence
            bkh: BinKeyHandler = self.__new_handler(iterations)
            pt: partial = partial(bkh.apply, data)
            randomized = await create_task(to_thread(pt))

        return randomized

    def reset(self) -> None:
        '''Reinitialize the instance.'''
        self._handlers.clear()
        self.__is_reset_needed = False
        self._log.debug("The instance was reset!")


class Extractor(Log):
    '''Extracts the original bytes sequence from the randomized one.

    Attributes:
        - ONE_BLOCK: Used for 'block_size' argument when you want to process
        the complete bytes sequence in one single block of data.
        - WORKERS (int): Number of worker for the ThreadPoolExecutor.
    '''
    ONE_BLOCK = -1
    WORKERS = 10

    def __init__(self, keys: List[List[Tuple[bytes, bytes]]]) -> None:
        '''Initializes the instance.

        Args:
            keys (List[List[Tuple[bytes, bytes]]]): A list of handlers keys.

        Raises:
            Exception: When keys is a empty list.
        '''
        Log.__init__(self)
        if not keys:
            raise Exception("Empty keys list was given!")

        self._handlers: List[BinKeyHandler] = []
        self._set_handler_keys(keys)

    def _set_handler_keys(self, keys: List[List[Tuple[bytes, bytes]]]) -> None:
        '''Creates a new list of handlers from `keys`.

        Args:
            keys (List[List[Tuple[bytes, bytes]]]): A list of handlers keys.

        Raises:
            Exception: When keys is a empty list.
        '''
        if not keys:
            raise Exception("Empty keys list was given!")

        for k in keys:
            self._handlers.append(BinKeyHandler(keys=k))

    def reverse(self, block_size: int, data: bytes) -> bytes:
        '''Extracts the original sequence from randomized byte sequence.

        The number of  ThreadPool workers is defined by `Extractor.WORKERS`.

        Args:
            - block_size (int): The block size used in the applied randomization.
            - data (bytes): The randomized byte sequence used to recover
            the original one.

        Returns: The original bytes sequence.
        '''
        original_sequence: bytes = b""

        # Process in blocks
        if block_size > 0:
            executor: ThreadPoolExecutor = ThreadPoolExecutor(
                max_workers=Randomizer.WORKERS)
            tasks: List[Future] = []
            s_block_size: str = format_bytes(block_size)

            self._log.debug(
                f"Extracting original sequence in blocks of {s_block_size}...")

            bkh_iterator: Iterator = iter(self._handlers)
            with BytesIO(data) as buffer, executor:
                while block := buffer.read(block_size):
                    bkh: BinKeyHandler = next(bkh_iterator)
                    tasks.append(executor.submit(bkh.reverse, block))
                    self._log.debug("Task added...")

            # Collect results
            self._log.debug("Waiting for tasks completion...")
            original_sequence = b"".join([t.result() for t in tasks])

        # Process in a single block
        else:
            self._log.debug("Extracting the entire sequence at once...")
            # Uses a single BinKey to extract the original data sequence
            original_sequence = self._handlers[0].reverse(data)

        return original_sequence

    async def reverse_async(self, block_size: int, data: bytes) -> bytes:
        '''Extracts the original sequence from randomized byte sequence.

        It must be called from a external event loop.
        Exmaple: `Asyncio.run(extractor.reverse_async(block_size, data))`

        Args:
            - block_size (int): The block size used in the applied randomization.
            - data (bytes): The randomized byte sequence used to recover
            the original one.

        Returns: The original bytes sequence.
        '''
        original_sequence: bytes = b""

        # Process in blocks
        if block_size > 0:
            tasks: List[Task] = []
            s_block_size: str = format_bytes(block_size)
            self._log.debug(
                f"Extracting original sequence in blocks of {s_block_size}...")
            bkh_iterator: Iterator = iter(self._handlers)
            with BytesIO(data) as buffer:
                while block := buffer.read(block_size):
                    bkh: BinKeyHandler = next(bkh_iterator)
                    pt: partial = partial(bkh.reverse, block)
                    tasks.append(create_task(to_thread(pt)))
                    self._log.debug("Task added...")

            # Collects and join blocks
            self._log.debug("Collecting and joining blocks...")
            original_sequence = b"".join(b for b in await gather(*tasks))

        # Process in a single block
        else:
            self._log.debug("Extracting the entire sequence at once...")
            # Uses a single BinKey to extract the original data sequence
            original_sequence = self._handlers[0].reverse(data)

        return original_sequence

    keys = property(fset=_set_handler_keys)
    keys.__doc__ = "Sets the handlers keys."