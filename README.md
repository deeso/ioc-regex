### Project description
This is a simple Python module that encapsulates regular expressions that can be imported and used.  The `ioc_regex.regex.IOCRegex` class can be used in several ways.  First, the regular expression for a given IOC type can be retrieved and used as a regular expression object.  Second, the user can pass
text, lines, or a single line that defangs and then extracts the values.

### Supported IOC Types

```
domain
ip
url
url_pot
hash_tag
email
md5
sha1
sha256
sha512
```

### Installation

**Python 3.X**: `pip3 install -I --force-reinstall -r requirements.txt .`
**Python 2.X**: `sudo pip install -I --force-reinstall -r requirements.txt .`

### Usage

```
content = 'ip1: 18.10[.]122[.]90 ip2: 19.12.121.1'
from ioc_regex.ir import IOCRegex
content = 'ip1: 18.10[.]122[.]90 ip2: 19.12.121.1'
results = IOCRegex.extract_all_possible(content)
results
print(results['ip4'], results['defanged_ip4'])
(['19.12.121.1'], ['18.10.122.90'])

# check if the results had anything useful
# checks defanged_* and email, ip4, url, url_pot, domain, and hashes
print IOCRegex.is_good_result(results)
True
    

```