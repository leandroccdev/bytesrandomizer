import logging
from copy import deepcopy
from unittest import (
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

if __name__ == "__main__":
    loader: TestLoader = TestLoader()
    ts: TestSuite = TestSuite()
    ts.addTests(loader.loadTestsFromTestCase(TestBinKey))
    runner = TextTestRunner(verbosity=1)
    runner.run(ts)