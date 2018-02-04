from ioc_regex import consts
from ioc_regex.ir import IOCRegex as IOCREX

import logging
from bs4 import BeautifulSoup, SoupStrainer
import requests
import json


class ContentHandler(object):

    def __init__(self, link=None, content=None, look_at_embedded_links=True):
        if content is None and link is None:
            raise Exception("Provide either a link or content to analyze")

        self.link = link
        self.expanded_link = False
        self.orig_link = link
        self.content = content
        self.content_type = 'html'
        self.response = None
        self.bs4_parser = None
        if self.link is not None and self.content is None:
            # download the link
            self.response = requests.get(self.link)
            self.content_type = self.response.headers['content-type']
            # read the contents
            if self.response.status_code == 200:
                self.content = self.response.text
                self.link = self.response.request.url
                logging.debug("Expanded link to: %s" % self.link)
                self.expanded_link = self.orig_link != self.link
            else:
                _m = "Unable to get the specified content:" +\
                     " HTTP STATUS CODE = %d"
                raise Exception(_m % self.response.status_code)

        if self.content_type.find('html') > -1 or \
           self.content_type.find('text/plain') > -1:
            self.bs4_parser = BeautifulSoup(self.content, 'html.parser')
        elif self.content_type.find('json'):
            # create key value mappings line by line
            json_data = json.loads(self.content)
            self.content = json.dumps(json_data, indent=0, sort_keys=True)
            self.bs4_parser = BeautifulSoup(self.content, 'html.parser')

        self.embedded_links = self.extract_embedded_links()

        self.artifacts = self.extract_all()

    @classmethod
    def create_content(cls, line):
        tokens = [w for w in line.split() if len(w) > 5]
        content = []
        for w in tokens:
            defanged_, dw = cls.check_and_defang(w)
            if not defanged_:
                content.append((w, None))
            else:
                content.append((w, dw))
        return content

    @classmethod
    def extract_domain_or_host(cls, line, defanged_only=False):
        r = {consts.IPS: [],
             consts.DOMAINS: [],
             consts.DF_DOMAINS: [],
             consts.DF_IPS: []}
        content = cls.create_content(line)
        for w, dw in content:
            domain = cls.R_DOMAIN_RE.search(w)
            ip = cls.R_IP_RE.search(w)
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

    def extract_embedded_links(self):
        urls = set()
        el_r = {consts.LINKS: [], consts.DOMAINS: [], consts.IPS: []}
        for link in BeautifulSoup(self.content, 'html.parser',
                                  parse_only=SoupStrainer('a')):
            line = None
            if 'href' in link:
                line = link['attrs']['href']

            if line is None or len(line) < 3:
                continue

            el = IOCREX.extract_link(line)
            el_r[consts.LINKS] = el_r[consts.LINKS] + el[consts.LINKS]
            el_r[consts.DF_LINKS] = el_r[consts.DF_LINKS] + el[consts.DF_LINKS]

            if len(el[consts.DF_LINKS]) > 0:
                for info in el[consts.DF_LINKS]:
                    url = info[consts.URL]
                    if url in urls:
                        continue
                    urls.add(url)

                    hi = IOCREX.extract_domain_or_host(url)
                    _t = el_r[consts.DF_IPS] + [i for i in hi[consts.DF_IPS]]
                    el_r[consts.DF_IPS] = _t
                    qs = [i for i in hi[consts.DF_DOMAINS]]
                    el_r[consts.DF_DOMAINS] = el_r[consts.DF_DOMAINS] + qs
                    x = el_r[consts.IPS] + [i for i in hi[consts.IPS]]
                    el_r[consts.DF_IPS] = sorted(set(x))
                    y = el_r[consts.DOMAINS] + [i for i in hi[consts.DOMAINS]]
                    el_r[consts.DF_DOMAINS] = sorted(set(y))

            if len(el[consts.LINKS]) > 0:
                for info in el[consts.LINKS]:
                    url = info[consts.URL]
                    if url in urls:
                        continue
                    urls.add(url)

                    hi = IOCREX.extract_domain_or_host(url)
                    x = el_r[consts.IPS] + [i for i in hi[consts.IPS]]
                    el_r[consts.IPS] = sorted(set(x))
                    y = el_r[consts.DOMAINS] + [i for i in hi[consts.DOMAINS]]
                    el_r[consts.DOMAINS] = sorted(set(y))
        return el_r

    def extract_all(self):
        content = self.content
        if content is None:
            return None

        return IOCREX.extract_all_possible(content)

    # def extract_all(self):
    #     lines = []
    #     if self.content is not None:
    #         ls = self.content.splitlines()
    #         lines = [i.strip() for i in ls if len(i.strip()) > 0]

    #     link_seen = set()
    #     ip_seen = set()
    #     hashes_seen = set()
    #     domain_seen = set()
    #     results = {consts.HASHES: [],
    #                consts.DOMAINS: [],
    #                consts.LINKS: [],
    #                consts.IPS: [],
    #                consts.DF_IPS: [],
    #                consts.DF_DOMAINS: [],
    #                consts.DF_LINKS: [], }

    #     for line in lines:
    #         results = IOCREX.get_host_info_update(line, results,
    #                                               ip_seen, domain_seen)
    #         uinfos = IOCREX.extract_link(line)
    #         if len(uinfos[consts.LINKS]) > 0:
    #             links = uinfos[consts.LINKS]
    #             _urls = results[consts.URLS]
    #             urls = set(IOCREX.links_to_urls(links) + _urls)
    #             results[consts.URLS] = urls

    #             hosts = IOCREX.extract_hosts_from_links(links)
    #             for host in hosts:
    #                 if IOCREX.possible_domain(host):
    #                     results[consts.DOMAINS].append(host)
    #                 elif IOCREX.possible_ip4(host):
    #                     results[consts.IPS].append(host)

    #         if len(uinfos[consts.DF_LINKS]) > 0:
    #             links = uinfos[consts.DF_LINKS]
    #             _urls = results[consts.DF_URLS]
    #             urls = set(IOCREX.links_to_urls(links) + _urls)
    #             results[consts.DF_URLS] = urls

    #             hosts = IOCREX.extract_hosts_from_links(links)
    #             for host in hosts:
    #                 if IOCREX.possible_domain(host):
    #                     results[consts.DF_DOMAINS].append(host)
    #                 elif IOCREX.possible_ip4(host):
    #                     results[consts.DF_IPS].append(host)

    #         hinfo = IOCREX.extract_hash(line)
    #         if len(hinfo[consts.HASHES]) > 0:
    #             g = [i for i in hinfo[consts.HASHES] if i not in hashes_seen]
    #             results[consts.HASHES] = results[consts.HASHES] + g
    #             hashes_seen |= set(g)

    #     # update hosts, domains, and urls from the actual results (redundant)
    #     hosts = IOCREX.extract_hosts_from_links(results[consts.LINKS])
    #     _df_links = results[consts.DF_LINKS]
    #     df_hosts = IOCREX.defang_extract_hosts_from_links(_df_links)

    #     for host in hosts:
    #         if IOCREX.possible_domain(host):
    #             results[consts.DOMAINS].append(host)
    #         elif IOCREX.possible_ip4(host):
    #             results[consts.IPS].append(host)

    #     for host in df_hosts:
    #         if IOCREX.possible_domain(host):
    #             results[consts.DF_DOMAINS].append(host)
    #         elif IOCREX.possible_ip4(host):
    #             results[consts.DF_IPS].append(host)

    #     clean_results = {
    #                 consts.URLS: sorted(set(results[consts.URLS])),
    #                 consts.DF_URLS: sorted(set(results[consts.DF_URLS])),
    #                 consts.IPS: sorted(set(results[consts.IPS])),
    #                 consts.DF_IPS: sorted(set(results[consts.DF_IPS])),
    #                 consts.DOMAINS: sorted(set(results[consts.DOMAINS])),
    #                 consts.DF_DOMAINS: sorted(set(results[consts.DF_DOMAINS])),
    #                 consts.HASHES: sorted(set(results[consts.HASHES])),
    #             }

    #     link_seen = set()
    #     for link in results[consts.LINKS]:
    #         x, y = link[consts.PROTO], link[consts.URL]
    #         if x+y in link_seen:
    #             continue
    #         link_seen.add(x+y)
    #         clean_results[consts.URLS].append(link)

    #     clean_results[consts.URLS] = sorted(set(clean_results[consts.URLS]))

    #     link_seen = set()
    #     for link in results[consts.DF_LINKS]:
    #         x, y = link[consts.PROTO], link[consts.URL]
    #         if x+y in link_seen:
    #             continue
    #         link_seen.add(x+y)
    #         clean_results[consts.DF_URLS].append(link)
    #     return clean_results
