from ioc_regex import consts
from ioc_regex.ir import IOCRegex as IOCREX

import logging
from bs4 import BeautifulSoup, SoupStrainer
import requests
import json

US = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36'


desktop_agents = ['Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
                 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
                 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
                 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/602.2.14 (KHTML, like Gecko) Version/10.0.1 Safari/602.2.14',
                 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36',
                 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.98 Safari/537.36',
                 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.98 Safari/537.36',
                 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36',
                 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
                 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0']
 
def random_headers():
    return {'User-Agent': choice(desktop_agents),'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'}

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
            self.response = requests.get(self.link, headers=random_headers())
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

        try:
            self.embedded_links = self.extract_embedded_links()
        except:
            self.embedded_links = []

        try:
            self.artifacts = IOCREX.extract_all_possible(content)
        except:
            self.artifacts = {}

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
