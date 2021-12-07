import re
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup


class Scanner:
    def __init__(self, url, ignore):
        self.session = requests.Session()
        self.url = url
        self.target_link = []
        self.ignore = ignore
        self.sqlurl = []

    def get_links(self, url):
        response = self.session.get(url)
        return re.findall('(?:href=")(.*?)"', response.text)

    def crawl(self, url=None):
        if url is None:
            url = self.url
        href_link = self.get_links(url)
        for link in href_link:
            link = urljoin(url, link)
            if '#' in link:
                link = link.split('#')[0]

            if self.url in link and link not in self.target_link and link not in self.ignore:
                self.target_link.append(link)
                if "=" in link:
                    self.sqlurl.append(link)
                print(link)
                self.crawl(link)

    def form_extracter(self, url):
        response = self.session.get(url)
        parsed_html = BeautifulSoup(response.content, 'html.parser')
        return parsed_html.findAll("form")

    def form_submit(self, form, value, url):
        action = form.get("action")
        method = form.get("method")
        action_url = urljoin(url, action)
        input_lit = form.findAll(["input", "textarea"])
        post_data = {}
        for inputt in input_lit:
            input_name = inputt.get('name')
            input_type = inputt.get('type')
            input_value = inputt.get('value')
            if input_type == 'text' or inputt == 'textarea':
                input_value = value
            post_data[input_name] = input_value
        if method == 'POST':
            return self.session.post(action_url, data=post_data)
        return self.session.get(action_url, params=post_data)

    def run_scanner(self, vulobj):
        for i, link in enumerate(self.target_link):
            flag = True
            forms = self.form_extracter(link)
            for form in forms:
                is_vulnerable, xss_payload = self.test_xss_in_form(form, link)
                if is_vulnerable:
                    vulobj.tree.insert("", i, text=link, value=(xss_payload, "XSS Found"))
                    flag = False

            if "=" in link:
                is_vulnerable, xss_payload = self.test_xss_in_link(link)
                if is_vulnerable:
                    vulobj.tree.insert("", i, text=link, value=(xss_payload, "XSS Found"))
                    flag = False
            if flag:
                vulobj.tree.insert("", i, text=link, value=('no match', "XSS Not Found"))

    def test_xss_in_form(self, form, url):
        with open('payloads.txt', 'r') as my_file:
            for xss_payload in my_file:
                r = self.form_submit(form, xss_payload, url)
                if xss_payload in r.text:
                    return True, xss_payload
        return False, xss_payload

    def test_xss_in_link(self, url):
        with open('payloads.txt', 'r') as my_file:
            for xss_payload in my_file:
                url = re.sub('=.*', '=' + xss_payload.encode('unicode_escape').strip(b'\\n').decode(), url)
                r = self.session.get(url)
                if xss_payload in r.text:
                    return xss_payload in r.text, xss_payload
        return False, xss_payload
