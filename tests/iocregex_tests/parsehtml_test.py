import unittest
import logging
from ioc_regex.ir import IOCRegex
from ioc_regex.consts import IP, DF_IP, DOMAIN, DF_DOMAIN

DATA = '''
<!-- saved from url=(0057)http://malware-traffic-analysis.net/2018/02/05/index.html -->
<html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8">

<ul>
<li>etlitttothen.com</li>
<li>witsemehat.net</li>
<li>hxxp://hwayou.com.tw/98ygubyr5?</li>
<li>hxxp://techknowlogix.net/98ygubyr5?</li>
</ul>

<ul>
<li>From: "Nathaniel  Lant" &lt;Nathaniel@sailslowdance.com&gt;</li>
<li>From: "Stefanie  Cockerall" &lt;Stefanie@sailslowdance.com&gt;</li>
</ul>
<ul>
<li><a class="menu_link" href="https://www.virustotal.com/#/file/a6b7a89a073be96dcfaac63ef0093e3186171995df90c9c3f966083338e858e9/detection">a6b7a89a073be96dcfaac63ef0093e3186171995df90c9c3f966083338e858e9</a> - SCAN_0502_FA2C8.pdf</li>
<li><a class="menu_link" href="https://www.virustotal.com/#/file/c327f7f91d942fa146c474ee052f838ed1ab49ef25db6dfdcaff3c7a5f7ba0f4/detection">c327f7f91d942fa146c474ee052f838ed1ab49ef25db6dfdcaff3c7a5f7ba0f4</a> - SCAN_0502_FF56B.pdf</li>
</ul>


<ul>
<li>hxxp://witsemehat.net/info/SCAN_0502_8A13.7z</li>
<li>hxxp://witsemehat.net/info/SCAN_0502_8A13.7z</li>
</ul>


<ul>
<li>hxxp://hwayou.com.tw/98ygubyr5?</li>
<li>hxxp://techknowlogix.net/98ygubyr5?</li>
</ul>


<ul>
<li>205.185.117.108 port 4431</li>
</ul>

<ul>
<li>212.92.98.171 port 80 - witsemehat.net</li>
</ul>
</body></html>
'''

DOMAIN_RESULTS = [
    'etlitttothen.com',
    'witsemehat.net',
    'www.virustotal.com',
    'malware-traffic-analysis.net',
    'sailslowdance.com'
]

DF_DOMAIN_RESULTS = [
    'etlitttothen.com',
    'witsemehat.net',
    'techknowlogix.net',
    'hwayou.com.tw',
]
IP_RESULTS = ['205.185.117.108', '212.92.98.171']


class ParsehtmlTest(unittest.TestCase):

    def test_ipextract(self):
        logging.debug("Performing HTML extract tests")
        self.assertTrue(IOCRegex.search(IP, DATA))
        results = IOCRegex.extract_all_possible(DATA)
        self.assertTrue(all([i in IP_RESULTS for i in results[IP]]))
        self.assertTrue(all([i in DOMAIN_RESULTS for i in results[DOMAIN]]))
        self.assertTrue(all([i in DF_DOMAIN_RESULTS for i in results[DF_DOMAIN]]))
