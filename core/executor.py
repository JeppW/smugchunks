import requests_raw as rawreq
from requests.exceptions import RequestException, ReadTimeout
from urllib.parse import urlparse
from datetime import datetime
from core.payloads import Payload, build_normal_req
from core.models import Finding
from core.logger import Logger

class Executor:
    MAX_ERRORS = 3

    def __init__(self, method="POST", urls=None, headers=None, timeout=7, output=None, findings_limit=2, quiet=False):
        self.method = method
        self.urls = urls or ["http://localhost/"]
        self.headers = headers or []

        self.timeout = timeout
        self.logger = Logger(log_filename=output, quiet=quiet)
        self.findings_limit = findings_limit

    def check_timeout(self, url, req):
        # checks if request causes a time delay
        try:
            rawreq.raw(url, req, timeout=self.timeout)
            return False
        except ReadTimeout:
            # timeout! this indicates vulnerability
            return True

    def test_target(self, url):
        try:
            parsed_url = urlparse(url)
            host = parsed_url.netloc
            path = parsed_url.path
        except ValueError as e:
            self.logger.error(f"An error occurred during URL parsing of '{url}': {e}. Skipping...")
            return

        # first, check if we can even perform a normal request
        # otherwise, we might confuse general non-responsiveness with a vulnerability
        try:
            if self.check_timeout(url, build_normal_req(host)):
                self.logger.error(f"Looks like host '{host}' isn't responding right now. Skipping...")
                return
        
        except RequestException as e:
            self.logger.error(f"An error occured during connectivity test for '{host}': {e.__class__.__name__}. Skipping...")
            return

        # then, attempt every variant of every payload
        findings = []
        network_errors = 0
        for payload in Payload.get_all_payloads():
            payload = payload(host=host, method=self.method, path=path, headers=self.headers)

            self.logger.info(f"Testing {host} for {payload.get_pretty_name()}...", overwritable=True)
            
            for title, req in payload.build_all():
                try:
                    if self.check_timeout(url, req):
                        # vulnerability identified!
                        findings.append(Finding(host, title, req, payload.is_gadget_required()))
                        break  # only report one vuln of the same type per host
                
                except RequestException as e:
                    # anything else that might go wrong 
                    self.logger.error(f"Unexpected error during {payload.get_pretty_name()} test on {host}: {e.__class__.__name__}")                  
                    network_errors += 1

                    # after too many of these, just stop and move on
                    if network_errors >= self.MAX_ERRORS:
                        self.logger.warning(f"Too many unexpected errors on {host}. Skipping...")
                        return
        
        if not findings:
            self.logger.info(f"No vulnerabilities found on {host}.")
            return

        # if we found a lot of "vulnerabilities", they're probably false positives
        # the user can configure this with --limit
        if len(findings) > self.findings_limit:
            self.logger.warning(f"{len(findings)} findings produced for {host}, these are probably false positives. To see them anyway, run with --limit {len(findings)}. Skipping...")
            return
        
        # try to reproduce each finding and report if reproducible
        # this is to prevent false positives caused by servers occasionally taking a long time to reply
        self.logger.info(f"Double-checking findings on {host}...", overwritable=True)
        for finding in findings:
            # first, see if it reproduces
            try:
                if self.check_timeout(url, finding.req):
                    # report the vulnerability
                    self.logger.finding(finding)
                else:
                    self.logger.warning(f"{finding.title} on {finding.host} identified, but failed double-check.")

            except RequestException as e:
                self.logger.error(f"Unexpected error during {finding.title} double-check on {finding.host}: {e.__class__.__name__}")


    def execute(self):
        self.logger.info(f"Starting smugchunks at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}...")
        
        for url in self.urls:
            url = url.strip()

            try:
                if not urlparse(url).scheme:
                    # looks like the user supplied a hostname instead of a URL
                    # no worries, we just add an https scheme
                    url = f"https://{url}"
            
            except ValueError as e:
                self.logger.error(f"An error occurred during URL parsing of '{url}': {e}. Skipping...")
                continue

            self.test_target(url)
            
        
        self.logger.info(f"Execution completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.")

