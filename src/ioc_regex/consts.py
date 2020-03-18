import regex
import random

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/602.2.14 (KHTML, like Gecko) Version/10.0.1 Safari/602.2.14',
    'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.98 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.98 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0'
]


def HEADERS():
    return {'User-Agent': random.choice(USER_AGENTS),
            'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'}


def rex_compile(pattern):
    return regex.compile(pattern)

TROJAN = u'trojan'
BACKDOOR = u'backdoor'
DROPPER = u'dropper'
RANSOMWARE = u'ransomware'
EXPLOIT_KIT = u'exploitkit'
WORM = u"worm"
VIRUS = u'virus'
APT = u'apt'
CRIMEWARE = u'crimeware'
INFORMATION_STEALER = u'infostealer'
MOBILE_TROJAN = 'umobile trojan'
CRYPTOMINING = u'cryptomining'
PHISHING = u'phishing'
MALWARE = u'malware'
SPYWARE = u'spyware'
ADWARE = u'adware'
INFRASTRUCTURE = u'infrastructure'
EMAIL = u'email'
URL = u'url'
DOMAIN = u'domain'
DOMAIN_PORT = u'domain_port'


COMMON_KEYWORD_CLASSIFICATION = [
    [u'adwind', TROJAN],
    [u'adylkuzz', TROJAN],
    [u'afraid', RANSOMWARE],
    [u'afriad', EXPLOIT_KIT],
    [u'agenttesla', RANSOMWARE],
    [u'angler', EXPLOIT_KIT],
    [u'afraid', RANSOMWARE],
    [u'alphacrypt', RANSOMWARE],
    [u'andromeda', TROJAN],
    [u'angler', EXPLOIT_KIT],
    [u'arescrypt', RANSOMWARE],
    [u'asprox', WORM],

    [u'backoff', TROJAN],
    [u'badrabbit', RANSOMWARE],
    [u'bandarchore', EXPLOIT_KIT],
    [u'bamital', TROJAN],
    [u'banjori', TROJAN],
    [u'bebloh', TROJAN],
    [u'bedep', TROJAN],
    [u'beebone', VIRUS],
    [u'blackenergy', APT],
    [u'brobot', TROJAN],
    
    [u'caphaw', TROJAN],
    [u'carbanak', APT],
    [u'cerber', RANSOMWARE],
    [u'conficker', WORM],
    [u'corebot', TROJAN],
    [u'cryptodefense', RANSOMWARE],
    [u'cryptolocker', RANSOMWARE],
    [u'cryptowall', RANSOMWARE],
    [u'cryptxxx', RANSOMWARE],
    [u'chthonic', TROJAN],
    [u'crypmic', RANSOMWARE],
    [u'cryptmic', RANSOMWARE],
    
    [u'darkleech', CRIMEWARE],
    [u'dexter', VIRUS],
    [u'dircrypt', RANSOMWARE],
    [u'dridex', TROJAN],
    [u'dyre', TROJAN],

    [u'eitest', TROJAN],
    [u'emotet', TROJAN],
    [u'explosive', APT],
    [u'fiesta', EXPLOIT_KIT],
    [u'fobber', INFORMATION_STEALER],
    [u'formbook', APT],
    
    [u'gameoverzeus', TROJAN],
    [u'zeus', TROJAN],
    [u'gandcrab', TROJAN],
    [u'geodo', TROJAN],
    [u'goodman', EXPLOIT_KIT],
    [u'gootkit', EXPLOIT_KIT],
    [u'globeimposter', APT],
    
    [u'hailstorm', TROJAN],
    [u'hancitor', TROJAN],
    [u'havex', TROJAN],
    [u'hesperbot', TROJAN],

    [u'icedid', TROJAN],
    [u'infinity', EXPLOIT_KIT],
    
    [u'jbitfrost', TROJAN],
    [u'jigsaw', TROJAN],

    [u'kaixin', EXPLOIT_KIT],
    [u'kelihos', TROJAN],
    [u'kraken', TROJAN],
    [u'kuluoz', TROJAN],
    
    [u'locky', RANSOMWARE],
    [u'locki', RANSOMWARE],
    
    [u'magnitude', EXPLOIT_KIT],
    [u'magnitudeek', EXPLOIT_KIT],
    [u'mask', TROJAN],
    [u'matsnu', BACKDOOR],
    [u'mirai', WORM],
    [u'murofet', TROJAN],

    [u'nebula', EXPLOIT_KIT],
    [u'necurs', TROJAN],
    [u'neutrino', EXPLOIT_KIT],
    [u'neurtrino', EXPLOIT_KIT],
    [u'neutrino', EXPLOIT_KIT],
    [u'njrat', TROJAN],
    [u'nuclear', EXPLOIT_KIT],
    [u'nyetya', RANSOMWARE],
    
    [u'odin', RANSOMWARE],

    [u'padcrypt', RANSOMWARE],
    [u'pandabanker', TROJAN],
    [u'petya', RANSOMWARE],
    [u'pony', EXPLOIT_KIT],
    [u'pseudo', RANSOMWARE],
    [u'pushdo', TROJAN],
    [u'pykspa', WORM],

    [u'qadars', TROJAN],
    [u'qakbot', TROJAN],
    [u'qbot', TROJAN],

    [u'ramdo', TROJAN],
    [u'ramnit', RANSOMWARE],
    [u'ranbyus', TROJAN],
    [u'reign', APT],
    [u'rig', EXPLOIT_KIT],
    [u'rigek', EXPLOIT_KIT],
    [u'rovnix', TROJAN],
    [u'rulan', DROPPER],

    [u'seamless', EXPLOIT_KIT],
    [u'shiotob', TROJAN],
    [u'sisron', TROJAN],
    [u'smokeloader', TROJAN],
    [u'sofacy', APT],
    [u'sundown', EXPLOIT_KIT],
    [u'suppobox', TROJAN],
    [u'sweetorange', APT],
    [u'symmi', TROJAN],

    [u'tempedreve', WORM],
    [u'terdot', TROJAN],
    [u'terror', EXPLOIT_KIT],
    [u'teslacrypt', RANSOMWARE],
    [u'tinba', TROJAN],
    [u'torrentlocker', RANSOMWARE],
    [u'trickbot', TROJAN],
 
    [u'upatre', TROJAN],
    [u'ursnif', TROJAN],
    
    [u'vawtrak', TROJAN],
    
    [u'wannacry', RANSOMWARE],
    [u'webcryptominer', TROJAN],
    [u'wirelurker', MOBILE_TROJAN],
    
    [u'xagent', TROJAN],
    [u'xpiro', TROJAN],
    
    [u'zbot', TROJAN],
    [u'zepto', RANSOMWARE],

    
    [u'cryptominer', CRYPTOMINING],
    [u'phishing', PHISHING],
    [u'url', URL],
    [u'domain', DOMAIN],
    [u'control panel', INFRASTRUCTURE],
    [u'exploitkit', MALWARE],
    [u'gate', INFRASTRUCTURE],
    [u'malware', MALWARE],
    [u'spyware', SPYWARE],
    [u'adware', ADWARE],
    [u'ransomware', RANSOMWARE],
    [u'botnet', INFRASTRUCTURE],

    [u'rat', TROJAN],
    [u'c2', INFRASTRUCTURE],
    [u'maldoc', MALWARE],
    [u'email', EMAIL],
    [u'powershell', MALWARE],
    [u'malware', MALWARE],
    [u'trojan', TROJAN],
    [u'compromised', TROJAN],
    [u'open directory', INFRASTRUCTURE],
    [u'opendirectory', INFRASTRUCTURE],
]

COMMON_URI_DEFANGS = [
    ('x', 't'),
    ('X', 't'),
    ('T', 't')
]
COMMON_DEFANGS = [('.]]', '.'),
                  ('[[.', '.'),
                  ('[.', '.'),
                  ('.]', '.'),
                  # ('hxxp', 'http'),
                  # ('htxp', 'http'),
                  # ('hxtp', 'http'),
                  # ('fxp', 'ftp'),
                  ('[:', ':'),
                  (':]', ':'),
                  ('[@', '@'),
                  ('@]', '@')]


COMMON_KEYWORDS = [
        ['adwind', 'adwind.*'],
        ['afraid', 'afraid.*'],
        ['afriad', 'afriad.*'],
        ['angler', 'angler.*'],
        ['arescrypt', 'arescrypt.*'],
        ['bandarchore', 'bandarchore.*'],
        ['cerber', 'cerber.*'],
        ['chthonic', 'chthonic.*'],
        ['crypmic', 'crypmic.*'],
        ['cryptmic', 'cryptmic.*'],
        ['cryptxxx', 'cryptxxx.*'],
        ['dridex', 'dridex$'],
        ['eitest', 'eitest'],
        ['emotet', 'emotet'],
        ['goodman', 'goodman'],
        ['gootkit', 'gootkit.*'],
        ['jbitfrost', 'jbitfrost.*'],
        ['kaixin', 'kaixin.*'],
        ['magnitude', 'magnitude.*'],
        ['magnitudeek', 'magnitudeek.*'],
        ['nebula', 'nebula.*'],
        ['neurtrino', 'neurtrino.*'],
        ['neutrino', 'neutrino.*'],
        ['pseudo', 'pseudo.*'],
        ['qbot', 'qbot.*'],
        ['ramnit', 'ramnit.*'],
        ['realstatistics', 'realstatistics.*'],
        ['rig', 'rig.*'],
        ['rulan', 'rulan.*'],
        ['seamless', 'seamless.*'],
        ['sundown', 'sundown.*'],
        ['terror', 'terror.*'],
        ['teslacrypt', 'teslacrypt.*'],
        ['badrabbit', 'badrabbit.*'],
        ['locky', 'locky.*'],
        ['locky', 'locki.*'],
        ['pandabanker', 'pandabankder.*'],
        ['seamless', 'seamless'],
        ['smokeloader', 'smokeloader.*'],
        # ['GENERIC_CryptTag', '.*crypt'],
        ['cryptominer', 'cryptominer'],
        ['phishing', '.*phishing'],
        ['url', 'url$'],
        ['url', 'urls$'],
        ['domain', 'domain$'],
        ['domain', 'domains$'],
        ['control panel', '[Cc]ontrol [Pp]anel$'],
        ['exploitkit', '^ek$'],
        ['exploitkit', 'exploit kit$'],
        ['gate', 'gate$'],
        ['malware', '[Mm]alware$'],
        ['spyware', 'spyware$'],
        ['adware', '[Aa]dware$'],
        ['ransomware', '$[Rr]ansomware'],
        ['botnet', '$[Bb]otnet'],
        ['black market', '$black market^'],
        ['underground', '$[Uu]nderground^'],
        ['rat', '.*[Rr][Aa][Tt]$'],
        ['c2', '[Cc]2$'],
        ['c2', 'command and control$'],
        ['maldoc', 'doc$'],
        ['email', 'email$'],
        ['maldoc', 'document$'],
        ['maldoc', 'maldoc$'],
        ['maldoc', 'malicious document$'],
        ['powershell', 'powershell$'],
        ['malware', 'sample$'],
        ['trojan', 'trojan$'],
        ['compromised', 'compromised$'],
        ['open directory', '.*open directory'],
        ['phishing', '.*phish.*']
        ]

COMMON_REMOVE_CHARS = ['&lt;', '&gt;', '<', '>', ',', '\n', '\t']
KEYWORDS = 'keyword'
R_COMMON_KEYWORDS = {p: regex.compile(p) for _, p in COMMON_KEYWORDS}

DEFANGED_RESULTS = 'defanged_results'
CLEAN_RESULTS = 'clean_results'
DEFANGED = "defanged"
PROTO = "proto"
HASH = "hash"
DOMAIN = "domain"
PORT = 'port'
URL = "url"
LINK = "link"
URI = 'uri'
IP = "ip4"
URL_POT = "url_pot"
EMAIL = "email"
MD5 = "md5"
SHA1 = "sha1"
SHA256 = "sha256"
SHA512 = "sha512"
HASH_TAG = "hashtag"
TAG = "tag"


HASHES = HASH + 'es'
DOMAINS = DOMAIN + 's'
DOMAIN_PORTS = DOMAIN_PORT + 's'
URLS = URL + 's'
LINKS = LINK + 's'
URIS = URI + 's'
IPS = IP + 's'
URL_POTS = URL_POT + 's'
EMAILS = EMAIL + 's'
MD5S = MD5 + 's'
SHA1S = SHA1 + 's'
SHA256S = SHA256 + 's'
SHA512S = SHA512 + 's'
TAGS = TAG + 's'

DF_HASH = "defanged_" + HASH
DF_DOMAIN = "defanged_" + DOMAIN
DF_DOMAIN_PORT = "defanged_" + DOMAIN_PORT
DF_URL = "defanged_" + URL
DF_LINK = "defanged_" + LINK
DF_URI = "defanged_" + URI
DF_IP = "defanged_" + IP
DF_URL_POT = "defanged_" + URL_POT
DF_EMAIL = "defanged_" + EMAIL
DF_MD5 = "defanged_" + MD5
DF_SHA1 = "defanged_" + SHA1
DF_SHA256 = "defanged_" + SHA256
DF_SHA512 = "defanged_" + SHA512

DF_HASHES = DF_HASH + 'es'
DF_DOMAINS = DF_DOMAIN + 's'
DF_DOMAIN_PORTS = DF_DOMAIN_PORT + 's'
DF_URLS = DF_URL + 's'
DF_LINKS = DF_LINK + 's'
DF_URIS = DF_URI + 's'
DF_IPS = DF_IP + 's'
DF_URL_POTS = DF_URL_POT + 's'
DF_EMAILS = DF_EMAIL + 's'
DF_MD5 = DF_MD5 + 's'
DF_SHA1 = DF_SHA1 + 's'
DF_SHA256 = DF_SHA256 + 's'
DF_SHA512 = DF_SHA512 + 's'

IOC_NAMES = [DOMAIN, IP, URL, URL_POT, EMAIL, MD5, SHA1, SHA256, SHA512]

DOMAIN_RE = r'((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$'
DOMAIN_PORT_RE = r'((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,}(?::[0-9]{1,5})?)$'
IP_RE = r'(?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))(?![0-9])'
URI_RE = r"(.\w+:\/\/)?([\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+)"
URL_RE = r"(h[xXtT][xXtT]p:\/\/|h[xXt][xXt]ps:\/\/)+[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?"
URL_POT_RE = r"[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?"
HASH_TAG_RE = r"#(\w+)"
EMAIL_RE = r"([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)"
MD5_RE = r"([a-fA-F\d]{32})"
SHA1_RE = r"([a-fA-F\d]{40})"
SHA256_RE = r"([a-fA-F\d]{64})"
SHA512_RE = r"([a-fA-F\d]{128})"

R_DOMAIN_RE = regex.compile(DOMAIN_RE)
R_DOMAIN_PORT_RE = regex.compile(DOMAIN_PORT_RE)
R_IP_RE = regex.compile(IP_RE)
R_URI_RE = regex.compile(URI_RE)
R_URL_RE = regex.compile(URL_RE)
R_URL_POT_RE = regex.compile(URL_POT_RE)
R_HASH_TAG_RE = regex.compile(HASH_TAG_RE)
R_EMAIL_RE = regex.compile(EMAIL_RE)
R_MD5_RE = regex.compile(MD5_RE)
R_SHA1_RE = regex.compile(SHA1_RE)
R_SHA256_RE = regex.compile(SHA256_RE)
R_SHA512_RE = regex.compile(SHA512_RE)
