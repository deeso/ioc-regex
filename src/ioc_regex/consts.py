import regex


def rex_compile(pattern):
    return regex.compile(pattern)

COMMON_DEFANGS = [('[.', '.'),
                  ('.]', '.'),
                  ('hxxp', 'http'),
                  ('htxp', 'http'),
                  ('hxtp', 'http'),
                  ('fxp', 'ftp'),
                  ('[:', ':'),
                  (':]', ':'),
                  ('[@', '@'),
                  ('@]', '@')]


COMMON_KEYWORDS = [
        ['adwind', '^adwind.*'],
        ['afraid', '^afraid.*'],
        ['afriad', '^afriad.*'],
        ['angler', '^angler.*'],
        ['arescrypt', '^arescrypt.*'],
        ['bandarchore', '^bandarchore.*'],
        ['cerber', '^cerber.*'],
        ['chthonic', '^chthonic.*'],
        ['crypmic', '^crypmic.*'],
        ['cryptmic', '^cryptmic.*'],
        ['cryptxxx', '^cryptxxx.*'],
        ['dridex', '^dridex$'],
        ['eitest', '^eitest.*'],
        ['emotet', '^emotet.*'],
        ['goodman', '^goodman.*'],
        ['gootkit', '^gootkit.*'],
        ['jbitfrost', '^jbitfrost.*'],
        ['kaixin', '^kaixin.*'],
        ['magnitude', '^magnitude.*'],
        ['magnitudeek', '^magnitudeek.*'],
        ['nebula', '^nebula.*'],
        ['neurtrino', '^neurtrino.*'],
        ['neutrino', '^neutrino.*'],
        ['pseudo', '^pseudo.*'],
        ['qbot', '^qbot.*'],
        ['ramnit', '^ramnit.*'],
        ['realstatistics', '^realstatistics.*'],
        ['rig', '^rig.*'],
        ['rulan', '^rulan.*'],
        ['seamless', '^seamless.*'],
        ['sundown', '^sundown.*'],
        ['terror', '^terror.*'],
        ['teslacrypt', '^teslacrypt.*'],
        ['badrabbit', '^badrabbit.*'],
        ['locky', '^locky.*'],
        ['pandabanker', '^pandabankder.*'],
        ['seamless', '^seamless'],
        ['smokeloader', '^smokeloader.*'],
        ['GENERIC_CryptTag', '^.*crypt'],
        ['phishing', '.*phishing'],
        ['url', '^url$'],
        ['url', '^urls$'],
        ['domain', '^domain$'],
        ['domain', '^domains$'],
        ['control panel', '^[Cc]ontrol [Pp]anel$'],
        ['exploitkit', '^ek'],
        ['exploitkit', '^exploit kit$'],
        ['gate', '^gate$'],
        ['malware', '^[Mm]alware$'],
        ['spyware', '^spyware$'],
        ['adware', '^[Aa]dware$'],
        ['open directory', '^open directory$'],
        ['ransomware', '$[Rr]ansomware'],
        ['botnet', '$[Bb]otnet'],
        ['black market', '$black market^'],
        ['underground', '$[Uu]nderground^'],
        ['rat', '.*[Rr][Aa][Tt]$'],
        ['c2', '^[Cc]2$'],
        ['c2', '^command and control$'],
        ['maldoc?', '^doc$'],
        ['email', '^email$'],
        ['maldoc?', '^document$'],
        ['maldoc', '^maldoc$'],
        ['maldoc', '^malicious document$'],
        ['powershell', '^powershell$'],
        ['malware', '^sample$'],
        ['trojan', '^trojan$'],
        ['compromised', '^compromised$'],
        ]

COMMON_REMOVE_CHARS = ['&lt;', '&gt;', '<', '>']
KEYWORDS = 'keywords'
R_COMMON_KEYWORDS = {p: regex.compile(p) for _, p in COMMON_KEYWORDS}

DEFANGED_RESULTS = 'defanged_results'
CLEAN_RESULTS = 'clean_results'
DEFANGED = "defanged"
PROTO = "proto"
HASH = "hash"
DOMAIN = "domain"
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
HASH_TAG = "tag"


HASHES = HASH + 'es'
DOMAINS = DOMAIN + 's'
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

DF_HASH = "defanged_" + HASH
DF_DOMAIN = "defanged_" + DOMAIN
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
DF_URLS = DF_URL + 's'
DF_LINKS = DF_LINK + 's'
DF_URIS = DF_URI + 's'
DF_IPS = DF_IP + 's'
DF_URL_POT = DF_URL_POT + 's'
DF_EMAILS = DF_EMAIL + 's'
DF_MD5 = DF_MD5 + 's'
DF_SHA1 = DF_SHA1 + 's'
DF_SHA256 = DF_SHA256 + 's'
DF_SHA512 = DF_SHA512 + 's'

IOC_NAMES = [DOMAIN, IP, URL, URL_POT, EMAIL, MD5, SHA1, SHA256, SHA512]

DOMAIN_RE = r'^((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$'
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
