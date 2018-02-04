import os
import logging
import sys
import unittest
import signal

from iocregex_tests.ips_test import IOCRegexIPTest
from iocregex_tests.parsehtml_test import ParsehtmlTest
from iocregex_tests.failed_tests import IOCRegexFailedTest

logging.getLogger().setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('[%(asctime)s - %(name)s] %(message)s')
ch.setFormatter(formatter)
logging.getLogger().addHandler(ch)


if __name__ == '__main__':

    unittest.main()
    os.kill(os.getpid(), signal.SIGKILL)
