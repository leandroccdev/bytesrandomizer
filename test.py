import logging
from copy import deepcopy
from unittest import (
        skip,
        TestCase,
        TestLoader,
        TestSuite,
        TextTestRunner
    )
from os import urandom
from bytesrandomizer import *

def setUpModule() -> None:
    logging.getLogger("bytesrandomizer").setLevel(logging.CRITICAL)

def tearDownModule() -> None:
    logging.getLogger("bytesrandomizer").setLevel(logging.ERROR)

# Size of data in bytes
DATA_LENGTH = 100

class TestBinKey(TestCase):
    def setUp(self) -> None:
        self._bka: BinKeyApplier = BinKeyApplier()
        self._bke: BinKeyExtractor = BinKeyExtractor(self._bka.key_a,
            self._bka.key_b)

    def tearDown(self) -> None:
        del self._bka
        del self._bke

    def test_apply_extract_bin_key(self) -> None:
        '''Test the correct operation of BinKeyApplier and
        BinKeyExtractor.'''
        global DATA_LENGTH
        data: bytes = urandom(DATA_LENGTH)
        randomized: bytes = self._bka.apply(data)
        self.assertGreater(len(randomized), 0)
        self.assertNotEqual(data, randomized)

        decoded: bytes = self._bke.extract(randomized)
        self.assertEqual(decoded, data)
        del randomized
        del data
        del decoded

    def test_apply_extract_in_place(self) -> None:
        '''Tests the correct in place operation of BinKeyApplier and
        BinKeyExtractor.
        '''
        global DATA_LENGTH
        data: bytearray = bytearray(urandom(DATA_LENGTH))
        original_data: bytearray = deepcopy(data)
        self._bka.apply_in_place(data)
        self.assertNotEqual(original_data, data)
        self.assertGreater(len(data), 0)

        self._bke.extract_in_place(data)
        self.assertEqual(original_data, data)
        del data
        del original_data

    def test_extractor_factory_new_from_hex_keys(self) -> None:
        '''Tests the correct operation of
        BinKeyExtractorFactory.new_from_hex_keys.
        '''
        global DATA_LENGTH
        bke = BinKeyExtractorFactory.new_from_hex_keys(
            self._bka.key_a.hex(), self._bka.key_b.hex())
        self.assertIsInstance(bke, BinKeyExtractor)

        data: bytes = urandom(DATA_LENGTH)
        randomized: bytes = self._bka.apply(data)
        extracted: bytes = bke.extract(randomized)
        self.assertGreater(len(randomized), 0)
        self.assertEqual(data, extracted)

        del bke
        del data
        del randomized
        del extracted


class TestRandomizer(TestCase):
    def setUp(self) -> None:
        self._randomizer: Randomizer = Randomizer()

    def tearDown(self) -> None:
        # del self._extractor
        del self._randomizer

    def test_apply(self) -> None:
        '''Test randomization/extraction without threads/processes.'''
        global DATA_LENGTH
        data: bytes = urandom(DATA_LENGTH)
        randomized: bytes = self._randomizer.apply(data)
        self.assertGreater(len(randomized), 0)

        self._extractor: Extractor = Extractor(self._randomizer.keys)
        extracted: bytes = self._extractor.extract(randomized)

        self.assertEqual(data, extracted)

    def test_no_data(self) -> None:
        '''Randomization test of an empty bytes sequence.'''
        global DATA_LENGTH
        data: bytes = b""
        with self.assertRaises(EmptyStreamError):
            self._randomizer.apply(data)
        data = b""
        with self.assertRaises(EmptyStreamError):
            self._randomizer.apply_tp(data, 0)
        data = b""
        with self.assertRaises(EmptyStreamError):
            self._randomizer.apply_pp(data, 0)

        del data

    def test_max_data_size(self) -> None:
        '''Tests Randomizer.MAX_SIZE validation at apply/apply_tp/apply_pp.'''
        max_size: int = Randomizer.MAX_SIZE
        Randomizer.MAX_SIZE = 10 # type: ignore
        data: bytes = b"-" * 20
        with self.assertRaises(ExceedsMemoryError):
            self._randomizer.apply(data)
            data = b"-" * 20
        with self.assertRaises(ExceedsMemoryError):
            self._randomizer.apply_tp(data, 1)
            data = b"-" * 20
        with self.assertRaises(ExceedsMemoryError):
            self._randomizer.apply_pp(data, 1)
        Randomizer.MAX_SIZE = max_size # type: ignore
        del data

    def test_reset_required(self) -> None:
        '''Tests the required reset at randomization process.'''
        global DATA_LENGTH
        data: bytes = urandom(DATA_LENGTH)
        with self.assertRaises(ResetRequiredError):
            self._randomizer.apply(data)
            self._randomizer.apply(data)
        self._randomizer.reset()
        data = urandom(DATA_LENGTH)
        with self.assertRaises(ResetRequiredError):
            self._randomizer.apply_tp(data, DATA_LENGTH)
            self._randomizer.apply_tp(data, DATA_LENGTH)
        self._randomizer.reset()
        data = urandom(DATA_LENGTH)
        with self.assertRaises(ResetRequiredError):
            self._randomizer.apply_pp(data, DATA_LENGTH)
            self._randomizer.apply_pp(data, DATA_LENGTH)
        self._randomizer.reset()
        del data

    def test_apply_workers_min_block_size(self) -> None:
        '''Tests the minimum block size for apply methods that uses workers.'''
        global DATA_LENGTH
        data: bytes = urandom(DATA_LENGTH)
        expected_msg: str = "'block_size' must be a positive integer!"
        with self.assertRaisesRegex(Exception, expected_msg):
            self._randomizer.apply_tp(data, -1)
        self._randomizer.reset()
        with self.assertRaisesRegex(Exception, expected_msg):
            self._randomizer.apply_pp(data, -1)
        del data
        del expected_msg

    def test_apply_workers_oversize_block_size(self) -> None:
        '''Tests block_size's oversize at apply_[tp|pp].'''
        global DATA_LENGTH
        data: bytes = urandom(DATA_LENGTH)
        with self.assertRaises(OversizedBlockError):
            self._randomizer.apply_tp(data, len(data) * 2)
        self._randomizer.reset()
        data = urandom(DATA_LENGTH)
        with self.assertRaises(OversizedBlockError):
            self._randomizer.apply_pp(data, len(data) * 2)
        del data

if __name__ == "__main__":
    loader: TestLoader = TestLoader()
    ts: TestSuite = TestSuite()
    ts.addTests(loader.loadTestsFromTestCase(TestBinKey))
    ts.addTest(loader.loadTestsFromTestCase(TestRandomizer))
    runner = TextTestRunner(verbosity=1)
    runner.run(ts)