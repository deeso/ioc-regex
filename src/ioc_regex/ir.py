from ioc_regex import consts
from .domain_util import possible_domain, possible_ip4, filter_domain
URLPARSE = None


try:
    from urllib.parse import urlparse as URLPARSE
except:
    pass

try:
    if URLPARSE is None:
        from urllib2 import urlparse as URLPARSE
except:
    pass


class IOCRegex(object):
    PATTERNS = {
        # consts.URI: consts.URI_RE,
        consts.DOMAIN: consts.DOMAIN_RE,
        consts.IP: consts.IP_RE,
        consts.URL: consts.URL_RE,
        consts.URL_POT: consts.URL_POT_RE,
        consts.HASH_TAG: consts.HASH_TAG_RE,
        consts.EMAIL: consts.EMAIL_RE,
        consts.MD5: consts.MD5_RE,
        consts.SHA1: consts.SHA1_RE,
        consts.SHA256: consts.SHA256_RE,
        consts.SHA512: consts.SHA512_RE,
    }

    REGEXS = {
        # consts.URI: consts.R_URI_RE,
        consts.DOMAIN: consts.R_DOMAIN_RE,
        consts.IP: consts.R_IP_RE,
        consts.URL: consts.R_URL_RE,
        consts.URL_POT: consts.R_URL_POT_RE,
        consts.HASH_TAG: consts.R_HASH_TAG_RE,
        consts.EMAIL: consts.R_EMAIL_RE,
        consts.MD5: consts.R_MD5_RE,
        consts.SHA1: consts.R_SHA1_RE,
        consts.SHA256: consts.R_SHA256_RE,
        consts.SHA512: consts.R_SHA512_RE,
    }

    @classmethod
    def search(cls, name, line):
        re = cls.regex(name)
        return re.search(line)

    @classmethod
    def regex(cls, name):
        if name not in cls.REGEXS:
            raise Exception("Regular expression not defined")
        return cls.REGEXS[name]

    @classmethod
    def pattern(cls, name):
        if name not in cls.PATTERNS:
            raise Exception("Regular expression not defined")
        return cls.PATTERNS[name]

    @classmethod
    def extract_value_must_contain(cls, name, data, mc=['.', '/']):
        res = []
        defanged = []
        # defang and split the string
        # 'a.a.a' min size of a string
        content = cls.convert_tokenize_line(data)
        for w, dw in content:
            e = w
            if not all([True if e.find(i) > -1 else False for i in mc]):
                continue

            v = cls.search(name, e)
            if v is not None and dw is not None:
                for g in v.captures():
                    defanged.append(g)
            elif v is not None:
                for g in v.captures():
                    res.append(g)

        return res, defanged

    @classmethod
    def extract_value(cls, name, data, treat_as_tokens=False):
        defanged = []
        res = []
        content = None
        if not treat_as_tokens:
            # defang and split the string
            content = cls.convert_tokenize_line(data)
        else:
            content = data
        # 'a.a.a' min size of a string
        # w is orginal term, and dw is the derived term if it was defanged
        for w, dw in content:
            e = w
            if dw is not None:
                e = dw

            v = cls.search(name, e)
            if v is not None and dw is not None:
                for g in v.captures():
                    defanged.append(g)
            elif v is not None:
                for g in v.captures():
                    res.append(g)
        return res, defanged

    @classmethod
    def undefang(cls, token, addl_defangs=[], remove_chars=[]):
        defangs = addl_defangs + consts.COMMON_DEFANGS
        nt = token
        # urls are case sensitive
        if nt.find("://") > -1:
            oscheme = nt.split('://')[0]
            nscheme = oscheme
            for o, n in consts.COMMON_URI_DEFANGS:
                nscheme = nscheme.replace(o, n)
            nt = nt.replace(oscheme, nscheme)

        for ov, nv in defangs:
            if nt.find(ov) > -1:
                nt = nt.replace(ov, nv)
        return nt

    @classmethod
    def check_and_undefang(cls, token, addl_defangs=[], remove_chars=[]):
        new_token = cls.undefang(token, addl_defangs=addl_defangs,
                                 remove_chars=remove_chars)

        if len(new_token) < 4:
            return False, token
        elif new_token.lower().strip() != token.lower().strip():
            return True, new_token
        return False, token

    @classmethod
    def is_valid_pot_url(cls, pot_url):
        if pot_url.find('://') == -1:
            pot_url = 'https://' + pot_url
        return cls.host_from_url(pot_url) is not None

    @classmethod
    def is_valid_url(cls, pot_url):
        return cls.host_from_url(pot_url) is not None

    @classmethod
    def extract_domain_or_host(cls, line, defanged_only=False):
        r = {consts.IPS: [],
             consts.DOMAINS: [],
             consts.DF_DOMAINS: [],
             consts.DF_IPS: []}
        content = cls.convert_tokenize_line(line)
        for w, dw in content:
            domain = cls.search(consts.DOMAIN, w)
            ip = cls.search(consts.IP, w)
            if ip is not None and dw is None:
                d = ip.captures()[0]
                r[consts.IPS].append(d)
            elif ip is not None:
                d = ip.captures()[0]
                r[consts.DF_IPS].append(d)

            if domain is not None and dw is not None:
                d = domain.captures()[0]
                # check domain tlds first
                if possible_domain(d):
                    r[consts.DF_DOMAINS].append(d)
            elif domain is not None:
                d = domain.captures()[0]
                # check domain tlds first
                if possible_domain(d):
                    r[consts.DOMAINS].append(d)

        return r

    @classmethod
    def host_from_url(cls, url):
        try:
            host = URLPARSE.urlsplit(url).netloc
            if cls.possible_domain(host):
                return host
            return None
        except:
            return None

    @classmethod
    def hosts_from_urls(cls, urls, force=False):
        hosts = []
        for url in urls:
            if force and url.find('://') == -1:
                url = 'http://' + url

            host = cls.host_from_url(url)
            if host is not None:
                hosts.append(host)
        return hosts

    @classmethod
    def links_to_urls(cls, links):
        urls = []
        for lv in links:
            if consts.URL in lv and consts.PROTO in lv:
                u = lv[consts.PROTO] + '://' + cls.undefang(lv[consts.URL])
                urls.append(u)
        return urls

    @classmethod
    def extract_host_from_link(cls, link):
        if consts.URL in link:
            _link = link[consts.URL]
            return cls.host_from_url("https://" + _link)
        return None

    @classmethod
    def defang_extract_host_from_link(cls, link):
        if consts.URL in link:
            df_link = cls.undefang(link[consts.URL])
            return cls.extract_host_from_link({consts.URL: df_link})
        return None

    @classmethod
    def extract_hosts_from_links(cls, links):
        hosts = []
        for link in links:
            host = cls.extract_hosts_from_link(link)
            if host is not None:
                hosts.append(host)
        return hosts

    @classmethod
    def extract_link(cls, line):
        r = {consts.LINKS: [], consts.DF_LINKS: []}
        b = [consts.PROTO, consts.URL]
        content = cls.convert_tokenize_line(line)
        for w, dw in content:
            f = cls.search(consts.URI, w)
            if w.find('http://') == 0 or w.find('https://') == 0:
                k = w.split('://')
                r[consts.DF_LINKS].append(dict(zip(b, k)))
            elif f is not None and dw is not None:
                proto, url = f.groups()
                if proto is not None:
                    proto = proto.strip('://')
                    k = [proto, url]
                    r[consts.DF_LINKS].append(dict(zip(b, k)))
            elif f is not None:
                proto, url = f.groups()
                if proto is not None:
                    proto = proto.strip('://')
                    k = [proto, url]
                    r[consts.LINKS].append(dict(zip(b, k)))

        return r

    @classmethod
    def convert_tokens(cls, tokens, addl_defangs=[], remove_chars=[]):
        content = []
        for w in tokens:
            defanged_, dw = cls.check_and_undefang(w,
                                                   addl_defangs=addl_defangs,
                                                   remove_chars=remove_chars)
            if not defanged_:
                content.append((w, None))
            else:
                content.append((w, dw))
        return content

    @classmethod
    def convert_tokenize_line(cls, line, addl_defangs=[], remove_chars=[]):
        if len(line.splitlines()) > 0:
            return cls.convert_tokenize_lines(line)
        tokens = [w for w in line.split() if len(w) > 5]
        return cls.convert_tokens(tokens, addl_defangs=addl_defangs,
                                  remove_chars=remove_chars)

    @classmethod
    def convert_tokenize_lines(cls, data, addl_defangs=[], remove_chars=[]):
        lines = [i.strip() for i in data.splitlines()]
        tokens = []
        for line in lines:
            tokens = tokens + [w for w in line.split() if len(w) > 5]
        return cls.convert_tokens(tokens, addl_defangs=addl_defangs,
                                  remove_chars=remove_chars)

    @classmethod
    def extract_hash(cls, line):
        r = {
                consts.HASHES: [],
                consts.MD5: [],
                consts.SHA1: [],
                consts.SHA256: [],
                consts.SHA512: [],
            }
        for w in line.split():
            md5 = cls.search(consts.MD5, w)
            sha1 = cls.search(consts.SHA1, w)
            sha256 = cls.search(consts.SHA256, w)
            sha512 = cls.search(consts.SHA512, w)
            h = None
            if sha512 is not None:
                h = sha512.captures()[0]
                r[consts.SHA512].append(h)
            if sha256 is not None:
                h = sha256.captures()[0]
                r[consts.SHA256].append(h)
            if sha1 is not None:
                h = sha1.captures()[0]
                r[consts.SHA1].append(h)
            if md5 is not None:
                h = md5.captures()[0]
                r[consts.MD5].append(h)
            if h is not None:
                r[consts.HASHES].append(h)
        return r

    @classmethod
    def extract_host(cls, s):
        if len(s.split('://')) > 1:
            s.split('://')[1].split('/')[0]
        return s

    @classmethod
    def only_domains(cls, lst):
        x = [i for i in lst if cls.possible_domain(i)]
        return cls.all_but_empty(x)

    @classmethod
    def only_ips(cls, lst):
        x = [i for i in lst if cls.possible_ip4(i)]
        return cls.all_but_empty(x)

    @classmethod
    def all_but_empty(cls, lst):
        return sorted([i for i in set(lst) if len(i) > 0])

    @classmethod
    def get_host_info_update(cls, line, results,
                             ip_seen=set(),
                             domain_seen=set()):
        hi = cls.extract_domain_or_host(line.lower())
        df_ips = results[consts.DF_IPS] + hi[consts.DF_IPS]
        df_domains = results[consts.DF_DOMAINS] + hi[consts.DF_DOMAINS]
        results[consts.DF_IPS] = cls.all_but_empty(df_ips)
        results[consts.DF_DOMAINS] = cls.all_but_empty(df_domains)

        ips = results[consts.IPS] + hi[consts.IPS]
        domains = results[consts.DOMAINS] + hi[consts.DOMAINS]
        results[consts.IPS] = cls.all_but_empty(ips)
        results[consts.DOMAINS] = cls.all_but_empty(domains)
        return results

    @classmethod
    def filter_email_domains_from_domains(cls, regex_results):
        email_domains = []
        for email in regex_results[consts.DF_EMAIL]:
            r = email.split('@')
            if len(r) != 2:
                continue
            domain = r[1].strip()
            email_domains.append(domain)

        for email in regex_results[consts.EMAIL]:
            r = email.split('@')
            if len(r) != 2:
                continue
            domain = r[1].strip()
            email_domains.append(domain)

        new_domains = []
        for domain in regex_results[consts.DF_DOMAIN]:
            if domain not in email_domains:
                new_domains.append(domain)

        regex_results[consts.DF_DOMAIN] = new_domains

        new_domains = []
        for domain in regex_results[consts.DOMAIN]:
            if domain not in email_domains:
                new_domains.append(domain)

        regex_results[consts.DOMAIN] = new_domains
        return regex_results

    @classmethod
    def possible_domain(cls, host):
        return possible_domain(host)

    @classmethod
    def possible_ip4(cls, host):
        return possible_ip4(host)

    @classmethod
    def extract_keywords(cls, data, treat_as_tokens=False,
                         addl_keywords=[],
                         remove_chars=[]):
        keywords = set()
        tokens = []
        if treat_as_tokens and isinstance(data, list):
            _tokens = data
            for w, dw in _tokens:
                if dw is None:
                    tokens.append(w)
                else:
                    tokens.append(dw)
        else:
            for c in remove_chars + consts.COMMON_REMOVE_CHARS:
                data = data.replace(c, ' ')
            tokens = [data, ]
            _tokens = cls.convert_tokenize_lines(data)
            for w, dw in _tokens:
                if dw is None:
                    tokens.append(w)
                else:
                    tokens.append(dw)

        keyword_rex = addl_keywords + consts.COMMON_KEYWORDS
        fail = False
        for keyword, pattern in keyword_rex:
            if fail:
                break
            if keyword in keywords:
                continue
            r = None
            if pattern in consts.R_COMMON_KEYWORDS:
                r = consts.R_COMMON_KEYWORDS.get(pattern)
            else:
                r = consts.rex_compile(pattern)
                consts.R_COMMON_KEYWORDS[pattern] = r

            for t in tokens:
                try:
                    if r.search(t):
                        keywords.add(keyword)
                        break
                except TypeError:
                    fail = True

        return sorted(keywords)

    @classmethod
    def is_good_result(cls, ioc_regex_results):
        t = [consts.DOMAIN, consts.IP, consts.URL,
             consts.URL_POT, consts.EMAIL, consts.URL_POT, ]
        checks = [i for i in t] + \
                 [consts.MD5, consts.SHA1,
                  consts.SHA256, consts.SHA512] + \
                 [consts.DEFANGED + "_" + i for i in t]

        r = []
        for i in checks:
            r.append(len(ioc_regex_results[i]) > 0)
        return any(r)

    @classmethod
    def get_url_results(cls, ioc_regex_results):
        return ioc_regex_results[consts.URL], \
               ioc_regex_results[consts.DF_URL]

    @classmethod
    def get_pot_url_results(cls, ioc_regex_results):
        return ioc_regex_results[consts.URL_POT], \
               ioc_regex_results[consts.DF_URL_POT]

    @classmethod
    def get_domain_results(cls, ioc_regex_results):
        return ioc_regex_results[consts.DOMAIN], \
               ioc_regex_results[consts.DF_DOMAIN]

    @classmethod
    def get_ip_results(cls, ioc_regex_results):
        return ioc_regex_results[consts.IP], \
               ioc_regex_results[consts.DF_IP]

    @classmethod
    def get_hash_results(cls, ioc_regex_results):
        return ioc_regex_results[consts.HASHES]

    @classmethod
    def extract_all_possible(cls, content, filter_email_domains=True,
                             addl_defangs=[], remove_chars=[],
                             addl_keywords=[]):

        for r in remove_chars + consts.COMMON_REMOVE_CHARS:
            content = content.replace(r, ' ')

        defanged_results = {consts.URI: []}
        clean_results = {consts.URI: []}
        # results = {'defanged_results': defanged_results,
        #            'clean_results': clean_results
        #            }

        tokens = cls.convert_tokenize_lines(content,
                                            addl_defangs=addl_defangs,
                                            remove_chars=remove_chars)
        hashes = [consts.MD5, consts.SHA1,
                  consts.SHA256, consts.SHA512]
        for name in cls.REGEXS.keys():
            cr, dfr = cls.extract_value(name, tokens, treat_as_tokens=True)
            if name == consts.URL:
                dfr = [i for i in dfr if cls.is_valid_url(i)]
                cr = [i for i in cr if cls.is_valid_url(i)]

            elif name == consts.URL_POT or name == consts.URI:
                dfr = [i for i in dfr if cls.is_valid_pot_url(i)]
                cr = [i for i in cr if cls.is_valid_pot_url(i)]

            if name in hashes:
                clean_results[name] = cls.all_but_empty(cr)
                continue

            clean_results[name] = cls.all_but_empty(cr)
            defanged_results[name] = cls.all_but_empty(dfr)

        domains = cls.hosts_from_urls(defanged_results[consts.URL])
        new_domains = defanged_results[consts.DOMAIN] + domains
        new_domains = cls.only_domains(new_domains)
        defanged_results[consts.DOMAIN] = new_domains

        domains = cls.hosts_from_urls(clean_results[consts.URL])
        new_domains = clean_results[consts.DOMAIN] + domains
        new_domains = cls.only_domains(new_domains)
        clean_results[consts.DOMAIN] = new_domains

        domains = cls.hosts_from_urls(defanged_results[consts.URL_POT], True)
        new_domains = defanged_results[consts.DOMAIN] + domains
        new_domains = cls.only_domains(new_domains)
        defanged_results[consts.DOMAIN] = new_domains

        domains = cls.hosts_from_urls(clean_results[consts.URL_POT], True)
        new_domains = clean_results[consts.DOMAIN] + domains
        new_domains = cls.only_domains(new_domains)
        clean_results[consts.DOMAIN] = new_domains

        hosts = cls.hosts_from_urls(defanged_results[consts.URL])
        new_hosts = defanged_results[consts.IP] + hosts
        new_hosts = cls.only_ips(new_hosts)
        defanged_results[consts.IP] = new_hosts

        hosts = cls.hosts_from_urls(clean_results[consts.URL])
        new_hosts = clean_results[consts.IP] + hosts
        new_hosts = cls.only_ips(new_hosts)
        clean_results[consts.IP] = new_hosts

        hosts = cls.hosts_from_urls(defanged_results[consts.URL_POT], True)
        new_hosts = defanged_results[consts.IP] + hosts
        new_hosts = cls.only_ips(new_hosts)
        defanged_results[consts.IP] = new_hosts

        hosts = cls.hosts_from_urls(clean_results[consts.URL_POT], True)
        new_hosts = clean_results[consts.IP] + hosts
        new_hosts = cls.only_ips(new_hosts)
        clean_results[consts.IP] = new_hosts

        domains = cls.hosts_from_urls(defanged_results[consts.URI])
        new_domains = defanged_results[consts.DOMAIN] + domains
        new_domains = cls.only_domains(new_domains)
        defanged_results[consts.DOMAIN] = new_domains

        domains = cls.hosts_from_urls(clean_results[consts.URI])
        new_domains = clean_results[consts.DOMAIN] + domains
        new_domains = cls.only_domains(new_domains)
        clean_results[consts.DOMAIN] = new_domains

        hosts = cls.hosts_from_urls(defanged_results[consts.URI])
        new_hosts = defanged_results[consts.IP] + hosts
        new_hosts = cls.only_ips(new_hosts)
        defanged_results[consts.IP] = new_hosts

        hosts = cls.hosts_from_urls(clean_results[consts.URI])
        new_hosts = clean_results[consts.IP] + hosts
        new_hosts = cls.only_ips(new_hosts)
        clean_results[consts.IP] = new_hosts

        clean_results[consts.IP] = cls.all_but_empty(clean_results[consts.IP])
        _t = cls.only_domains(clean_results[consts.DOMAIN])
        clean_results[consts.DOMAIN] = _t
        uris_urls = clean_results[consts.URI] + clean_results[consts.URL]
        uris_urls = cls.all_but_empty(uris_urls)
        clean_results[consts.URL] = uris_urls
        del clean_results[consts.URI]
        _t = cls.all_but_empty(defanged_results[consts.IP])
        defanged_results[consts.IP] = _t
        _t = cls.only_domains(defanged_results[consts.DOMAIN])
        defanged_results[consts.DOMAIN] = _t
        uris_urls = defanged_results[consts.URI] + defanged_results[consts.URL]
        uris_urls = cls.all_but_empty(uris_urls)
        defanged_results[consts.URL] = uris_urls
        del defanged_results[consts.URI]

        results = {}
        for k, v in clean_results.items():
            results[k] = v

        for k, v in defanged_results.items():
            results[consts.DEFANGED + "_" + k] = v

        results = cls.filter_email_domains_from_domains(results)
        remove_chars = ['#', ] + remove_chars
        keywords = cls.extract_keywords(content,
                                        addl_keywords=addl_keywords,
                                        remove_chars=remove_chars,
                                        treat_as_tokens=False)
        results[consts.KEYWORDS] = keywords
        hashes_s = [consts.MD5, consts.SHA1,
                    consts.SHA256, consts.SHA512]

        hashes = []
        for k in hashes_s:
            hashes = hashes + results[k]

        results[consts.HASHES] = sorted(set(hashes))
        return results

    @classmethod
    def extract_all_possible_rate(cls, content, filter_email_domains=True,
                                  addl_defangs=[], remove_chars=[],
                                  addl_keywords=[]):

        results = cls.extract_all_possible(content,
                                           filter_email_domains=True,
                                           addl_defangs=addl_defangs,
                                           remove_chars=remove_chars,
                                           addl_keywords=addl_keywords)
        return cls.is_good_result(results), results

    @classmethod
    def filter_domain(cls, domain):
        return filter_domain(domain)
