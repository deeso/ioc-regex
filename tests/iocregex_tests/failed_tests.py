import logging
import unittest
from ioc_regex.ir import IOCRegex
from ioc_regex.consts import URL_POT, DF_DOMAIN


DATA2 = 'badguys[.]com[.]tr/abc1234.exe'

class IOCRegexFailedTest(unittest.TestCase):

    def test_ipextract(self):
        logging.debug("Performing extract tests on things that failed and shouldnt")
        self.assertTrue(IOCRegex.search(URL_POT, DATA2))
        w, dw = IOCRegex.extract_value(URL_POT, DATA2)
        self.assertTrue(len(w) == 0 and len(dw) == 1)
        self.assertTrue(dw[0] == IOCRegex.defang(DATA2))
        results = IOCRegex.extract_all_possible(DATA2)
        self.assertTrue('badguys.com.tr' in results[DF_DOMAIN])
