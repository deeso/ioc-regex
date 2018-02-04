### Project description
This is a simple Python module that encapsulates regular expressions that can be imported and used.  The `ioc_regex.regex.IOCRegex` class can be used in several ways.  First, the regular expression for a given IOC type can be retrieved and used as a regular expression object.  Second, the user can pass
text, lines, or a single line that defangs and then extracts the values.

### Supported IOC Types

```
domain
ip
uri
url
url_pot
hash_tag
email
md5
sha1
sha256
sha512
```