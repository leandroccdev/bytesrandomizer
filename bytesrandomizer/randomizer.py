from .exceptions import *
from .util import ListEndlessIterator, format_bytes
from concurrent.futures import Future, ThreadPoolExecutor, ProcessPoolExecutor
from multiprocessing import cpu_count
from secrets import SystemRandom
from struct import pack, unpack
from typing import (
        Dict,
        Iterator,
        List,
        Optional,
        NewType,
        NoReturn,
        Tuple,
        TypeAlias,
        Union
    )
import logging

# Setup logger
logger = logging.getLogger(__name__)

# Custom types
Key = NewType("Key", Tuple[bytes, bytes])
Keys = NewType("Keys", List[Key])
Executor_Pool: TypeAlias = Union[ProcessPoolExecutor, ThreadPoolExecutor]

class Log:
    '''Provides an internal logger instance.'''

    def __init__(self) -> None:
        '''Initialize the instance.'''
        global logger
        self._log: logging.Logger = logger.getChild(self.__class__.__name__)


class BinKeyApplier:
    '''Applies randomization key into a byte sequences.'''

    def __init__(self) -> None:
        '''Initialize the instance.

        key_a and key_b records are created automatically. Each records is
        shuffled once.

        '''
        # Creates key a record
        l: List[int] = list(range(256))
        SystemRandom().shuffle(l)
        self._key_a: Dict[int, int] = dict(enumerate(l))

        # Creates key b record
        self._key_b: List[int] = list(range(256))
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
        '''Randomizes the byte sequence `data`.

        Args:
            data (bytes): the byte sequence to be randomized.

        Returns: The randomized byte sequence.
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
    '''Recovers the original byte sequence from a randomized one.'''

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
        '''Recovers the original byte sequence from a randomized one.

        Args:
            data (bytes): The randomized byte sequence used to recover the
            original one.

        Returns: The original byte sequence.
        '''
        r_data: List[int] = []
        for b in data:
            r_data.append(
                self._key_a[b] ^ ListEndlessIterator(self._key_b).__next__())
        return bytes(r_data)

    def extract_in_place(self, data: bytearray) -> None:
        '''Recovers the original byte sequence from a randomized one.

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


class Randomizer(Log):
    '''Randomizes a sequence of bytes using BinKeys.

    Attributes:
        - CORES (int): The number of logical cores in the CPU.
        - MAX_SIZE (int): The maximum size of the byte sequence randomizer
        handles.
        - WORKERS (int): Number of worker for the ThreadPoolExecutor
    '''
    CORES = cpu_count()
    MAX_SIZE = 104857600 # 100 MB (in bytes).
    WORKERS = 5

    def __init__(self) -> None:
        '''Initializes the instance.

        Raises:
            ExceedsMaximumSizeError: When data byte sequence size is greater
            than Randomizer.MAX_SIZE. (The limit can be adjusted).
        '''
        Log.__init__(self)
        self._handlers: List[BinKeyApplier] = []
        # Flag: indicates when this instance requires a reset
        self.__is_reset_needed: bool = False

    def __check_reset_needed(self) -> None:
        '''Check if this instance requires a reset.

        Raises:
            ResetRequiredError: When try to apply/reverse a sequence before
            resets the instance.
        '''
        if self.__is_reset_needed:
            raise ResetRequiredError("Reset is required!")

    def __new_handler(self) -> BinKeyApplier:
        '''Adds new handler to internal list.'''
        bkah: BinKeyApplier = BinKeyApplier()
        self._handlers.append(bkah)
        return bkah

    def __validate_max_data_size(self, data: bytes) -> Optional[NoReturn]:
        '''Validates the maximum data size allowed by Randomizer.MAX_SIZE.

        Args:
            data (bytes): The byte sequence to be validated.
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

    def __apply_with_executor(self, data: bytes, block_size: int,
        executor: Executor_Pool) -> bytes:
        '''Randomizes a byte sequence using a executor pool.

        Args:
            - data (bytes): The sequence of bytes to be randomized.
            - block_size (int): Amount of bytes to be randomized with
            same BinKey before generates new one.
            - executor (Union[ThreadPoolExecutor, ProcessPoolExecutor]): The
            executor to use in the process.

        Returns: A randomized byte sequence.
        '''
        # Process in blocks of block_size
        tasks: List[Future] = []
        f_block_size: str = format_bytes(block_size)
        self._log.debug(f"Randomizing in blocks of {f_block_size}...")
        # The use of a for (instead BytesIO) is give us more stable execution
        # times
        with executor:
            last: int = 0
            for i in range(block_size, len(data), block_size):
                block: bytes = data[last:i]
                bka: BinKeyApplier = self.__new_handler()
                tasks.append(executor.submit(bka.apply, block))
                last = i

            # Process last block
            if last < len(data):
                block: bytes = data[last:]
                bka: BinKeyApplier = self.__new_handler()
                tasks.append(executor.submit(bka.apply, block))

        # Collect results
        self._log.debug("Waiting for tasks completion...")
        return b"".join([t.result() for t in tasks])

    @property
    def keys(self) -> Keys:
        '''List of handlers keys.'''
        return Keys([Key((h.key_a, h.key_b)) for h in self._handlers])

    def apply(self, data: bytes) -> bytes:
        '''Randomizes a byte sequence synchronously as one block.

        Args:
            - data (bytes): The sequence of bytes to be randomized.

        Raises:
            - ExceedsMemoryErro: When Randomizer.MAX_SIZE is exceeded
            - ResetRequiredError: When the instance is expecting a reset.

        Returns: A randomized byte sequence.
        '''
        self.__check_reset_needed()
        self.__validate_max_data_size(data)
        self.__is_reset_needed = True

        # Process in a single block
        return self.__new_handler().apply(data)

    def apply_tp(self, data: bytes, block_size: int) -> bytes:
        '''Randomizes a byte sequence using a ThreadPool.

        The number of  ThreadPool workers is defined by `Randomizer.WORKERS`.

        Args:
            - data (bytes): The sequence of bytes to be randomized.
            - block_size (int): Amount of bytes to be randomized with
            same BinKey before generates new one.

        Raises:
            - ExceedsMemoryErro: When Randomizer.MAX_SIZE is exceeded
            - ResetRequiredError: When the instance is expecting a reset.

        Returns: A randomized byte sequence.
        '''
        self.__check_reset_needed()
        self.__validate_max_data_size(data)
        self.__is_reset_needed = True

        # Checks block_size
        if block_size <= 0:
            raise Exception("'block_size' must be a positive integer!")

        # Process in blocks of block_size
        return self.__apply_with_executor(data, block_size,
            ThreadPoolExecutor(max_workers=Randomizer.WORKERS))

    def apply_pp(self, data: bytes, block_size: int) -> bytes:
        '''Randomizes a byte sequence using a ProcessPool.

        This is usually faster than `apply` and `apply_tp` alternatives.
        The number of workers is defined by `Randomizer.CORES` (taken from
        multiprocessing.cpu_count()).

        Args:
            - data (bytes): The sequence of bytes to be randomized.
            - block_size (int): Amount of bytes to be randomized with
            same BinKey before generates new one.

        Raises:
            - ExceedsMemoryErro: When Randomizer.MAX_SIZE is exceeded
            - ResetRequiredError: When the instance is expecting a reset.

        Returns: A randomized byte sequence.
        '''
        self.__check_reset_needed()
        self.__validate_max_data_size(data)
        self.__is_reset_needed = True

        # Checks block_size
        if block_size <= 0:
            raise Exception("'block_size' must be a positive integer!")

        # Process in blocks of block_size
        return self.__apply_with_executor(data, block_size,
            ProcessPoolExecutor(max_workers=Randomizer.CORES))

    def reset(self) -> None:
        '''Reinitialize the instance.'''
        self._handlers.clear()
        self.__is_reset_needed = False
        self._log.debug("The instance was reset!")


class Extractor(Log):
    '''Extracts the original byte sequence from the randomized one.

    Attributes:
        - CORES (int): The number of logical cores in the CPU.
        - ONE_BLOCK: Used for 'block_size' argument when you want to process
        the complete byte sequence in one single block of data.
        - WORKERS (int): Number of worker for the ThreadPoolExecutor.
    '''
    CORES = cpu_count()
    ONE_BLOCK = -1
    WORKERS = 5

    def __init__(self, keys: Keys) -> None:
        '''Initializes the instance.

        Args:
            keys (Keys): A list of handlers keys.

        Raises:
            Exception: When keys is a empty list.
        '''
        Log.__init__(self)
        if not keys:
            raise Exception("Empty keys list was given!")

        self._handlers: List[BinKeyExtractor] = []
        self._set_handler_keys(keys)

    def __extract_with_executor(self, data: bytes, block_size: int,
        executor: Executor_Pool) -> bytes:
        '''Extracts the original sequence from randomized one using a executor.

        Args:
            - block_size (int): The block size used in the applied randomization.
            - data (bytes): The randomized byte sequence used to recover
            the original one.
            - executor (Union[ThreadPoolExecutor, ProcessPoolExecutor]): The
            executor to use in the process.

        Returns: The original byte sequence.
        '''
        tasks: List[Future] = []
        s_block_size: str = format_bytes(block_size)
        self._log.debug(
            f"Extracting original sequence in blocks of {s_block_size}...")

        bke_iterator: Iterator = iter(self._handlers)
        with executor:
            last: int = 0
            for i in range(block_size, len(data), block_size):
                block: bytes = data[last:i]
                bke: BinKeyExtractor = next(bke_iterator)
                tasks.append(executor.submit(bke.extract, block))
                last = i

            # Process last block
            if last < len(data):
                block: bytes = data[last:]
                bke: BinKeyExtractor = next(bke_iterator)
                tasks.append(executor.submit(bke.extract, block))

        # Collect results
        self._log.debug("Waiting for tasks completion...")
        return b"".join([t.result() for t in tasks])

    def _set_handler_keys(self, keys: Keys) -> None:
        '''Creates a new list of handlers from `keys`.

        Args:
            keys (Keys): A list of handlers keys.

        Raises:
            Exception: When keys is a empty list.
        '''
        if not keys:
            raise Exception("Empty keys list was given!")

        for a, b in keys:
            self._handlers.append(BinKeyExtractor(a, b))

    def extract(self, data: bytes) -> bytes:
        '''Extracts the original sequence from randomized one.

        The processing of `data` is done as single block in synchronous mode.

        Args:
            data (bytes): The randomized byte sequence used to recover
            the original one.

        Returns: The original byte sequence.
        '''
        return self._handlers[0].extract(data)

    def extract_tp(self, data: bytes, block_size: int) -> bytes:
        '''Extracts the original sequence from randomized one.

        The number of  ThreadPool workers is defined by `Extractor.WORKERS`.

        Args:
            - block_size (int): The block size used in the applied randomization.
            - data (bytes): The randomized byte sequence used to recover
            the original one.

        Returns: The original byte sequence.
        '''
        # Checks block_size
        if block_size <= 0:
            raise Exception("'block_size' must be a positive integer!")

        return self.__extract_with_executor(data, block_size,
            ThreadPoolExecutor(max_workers=Randomizer.WORKERS))

    def extract_pp(self, data: bytes, block_size: int) -> bytes:
        '''Extracts the original sequence from randomized one.

        This is usually faster than `extract` and `extract_tp` alternatives.
        The number of workers is defined by `Extractor.CORES` (taken from
        multiprocessing.cpu_count()).

        Args:
            - block_size (int): The block size used in the applied randomization.
            - data (bytes): The randomized byte sequence used to recover
            the original one.

        Returns: The original byte sequence.
        '''
        # Checks block_size
        if block_size <= 0:
            raise Exception("'block_size' must be a positive integer!")

        return self.__extract_with_executor(data, block_size,
            ProcessPoolExecutor(max_workers=Randomizer.WORKERS))

    keys = property(fset=_set_handler_keys)
    keys.__doc__ = "Sets the handlers keys."


class KeyExporter(Log):
    '''Exports the `Randomizer` keys to a byte secuence.

    Attributes:
        MARK (bytes): Binary seal designed to recognize a binary key.
    '''
    MARK: bytes = b"BK"

    def __init__(self, randomizer: Randomizer) -> None:
        '''Initializes the KeyExporter instance.

        Raises:
            Exception: When the randomizer instance has an empty keys list.
        '''
        Log.__init__(self)
        # Randomizer has an empty keys list
        if not randomizer.keys:
            raise Exception("Empty keys list was given!")

        self._keys: Keys = randomizer.keys

    def export_keys(self) -> bytes:
        '''Exports the Randomizer keys into a byte sequence.

        Returns: The keys used for `Randomizer` instance as single byte sequence.
        '''
        self._log.debug("Exporting keys...")
        keys: List[bytes] = []

        self._log.debug("Packing keys list...")
        # Converts self._keys into single byte sequence
        # k: a tuple of two key records (key_a, key_b)
        fmt: str = "<" + "".join(["256s256s" for k in self._keys])
        keys: List[bytes] = []
        for a,b in self._keys:
            keys.append(a)
            keys.append(b)
        # Debug: To print the length of items at keys list
        # print([len(e) for e in keys])
        # Debug: To print the format for pack function
        # print(fmt)
        content: bytes = pack(fmt, *keys)

        # Adds a header to the data to enable future reading
        # Header structure:
        # [header length]\x00[header]\x00[content]
        header_data: bytes = f"{len(fmt)}\x00{fmt}\x00".encode("utf-8")
        fmt_header = f"<{len(header_data)}s"
        header: bytes = pack(fmt_header, header_data)

        # Joins header and content
        return KeyExporter.MARK + b"\x00" + header + content


class KeyImporter(Log):
    '''Imports a `Extractor` keys from a byte sequence.

    Attributes:
        SEPARATOR (bytes): Binary separator.
    '''
    SEPARATOR: bytes = b"\x00"

    def __init__(self) -> None:
        '''Initialize the instance.'''
        Log.__init__(self)

    def is_valid(self, data: bytes) -> bool:
        '''Verifies if the given key is a valid one.

        Args:
            data (bytes): The key as a byte sequence.

        Returns: True when data is a valid key. False otherwise.
        '''
        return data.split(KeyImporter.SEPARATOR)[0] == KeyExporter.MARK

    def import_keys(self, data: bytes) -> Union[Keys, NoReturn]:
        '''Imports the keys used for `Extractor` instance from a byte sequence.

        Raises:
            - InvalidKeyError: When the byte sequence read is wrong or can't be
            read.

        Returns: A `keys` list.
        '''
        if not self.is_valid(data):
            err: str = "The given key is invalid!"
            self._log.error(err)
            raise InvalidKeyError(err)

        try:
            self._log.debug('Importing the keys...')
            # Avoid MARK
            data = data[3:]
            header_len_b: bytes = data.split(KeyImporter.SEPARATOR)[0]
            header_len: int = int(header_len_b.decode("utf-8"))
            # Move to header format
            data = data[len(header_len_b) + 1:]
            header_fmt: str = data[:header_len].decode("UTF-8")
            # Move to data section
            data = data[len(header_fmt) + 1:]

            keys: Keys = [] # type: ignore
            key_data: Tuple[bytes] = unpack(header_fmt, data)
            for i in range(0, len(key_data), 2):
                key: Key = Key((key_data[i], key_data[i + 1]))
                keys.append(key)
            return keys
        except Exception as e:
            self._log.error(e)
            raise InvalidKeyError("Unable to read the key header!")