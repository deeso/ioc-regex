import logging
import unittest
from ioc_regex.ir import IOCRegex
from ioc_regex.consts import IP, DF_IP

EXP_IP_VALUE = '31.3.230.31'
DF_EXP_IP_VALUE = '31.3.230.32'
DATA = '''rtf:
https://www.hybrid-analysis.com/sample/6d5d461af97cc7d108f2df6e6cc8bf0198dbd1a0d87952af9d45127f12b2d5c7?environmentId=110

rar->exe
https://www.hybrid-analysis.com/sample/10ea8d9ccccce59ae420fe5b0ac0488fa136f6fbd3faa6747a198c25577f968f?environmentId=110

open dir:
http://31.3.230.31/bin/
http://31.3[.]230[.]32/bin/

http://justloki.com/Angel/five/
http://puttypot.info/Earl/five
http://houmehr.ir/cil/ddsssfsa/dwfwwe/dawas/eadewfe/Panel/
http://salesxpert.biz/Nwa/five/'''

class IOCRegexIPTest(unittest.TestCase):

    def test_ipextract(self):
        logging.debug("Performing IP extract tests")
        self.assertTrue(IOCRegex.search(IP, DATA))
        results = IOCRegex.extract_all_possible(DATA)
        self.assertTrue(len(results[DF_IP]) == 1)
        self.assertTrue(len(results[IP]) == 1)
        ip = results[IP][0]
        self.assertTrue(ip == EXP_IP_VALUE)
        ip = results[DF_IP][0]
        self.assertTrue(ip == DF_EXP_IP_VALUE)
