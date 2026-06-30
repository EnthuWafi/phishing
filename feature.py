import re
import socket
import requests
from bs4 import BeautifulSoup
from googlesearch import search
from urllib.parse import urlparse

class FeatureExtractor:

    def __init__(self,url):
        """
        Top Features to be parsed: 
        ['PrefixSuffix-', 'SubDomains', 'HTTPS', 
        'AnchorURL', 'LinksInScriptTags', 'WebsiteTraffic']
        """
        self.url = url
        self.domain = ""
        self.base_domain = ""
        self.parsed_url = None
        self.response = None
        self.soup = None

        # Standardize initial input format
        initial_url = url if "://" in url else "https://" + url

        # Execute live network request first to follow the redirect chain
        try:
            # requests.get automatically follows redirects by default
            self.response = requests.get(initial_url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
            
            # Capture the true final landing URL after all redirects complete
            final_url = self.response.url
        except requests.RequestException:
            self.soup = None
            final_url = initial_url

        # Parse the verified landing URL structure safely
        try:
            self.parsed_url = urlparse(final_url)
            self.domain = self.parsed_url.netloc

            # Strip port numbers if present in the network location string
            if ":" in self.domain:
                self.domain = self.domain.split(":")[0]

            domain_parts = self.domain.split('.')
            self.base_domain = '.'.join(domain_parts[-2:]) if len(domain_parts) >= 2 else self.domain
        except Exception:
            self.domain = ""
            self.base_domain = ""

    
    # Scammers commonly use hyphens to create lookalike brand domains
    def prefixSuffix(self):
        if not self.domain:
            return -1    
        return -1 if '-' in self.domain else 1
    
    def subDomains(self):
        if not self.domain:
            return -1
        
        # Clean 'www.' out to prevent false inflation of subdomain counts
        clean_domain = self.domain.replace("www.", "")
        dot_count = clean_domain.count(".")
        
        # Standard domains have 1 dot (example.com). 
        # Single subdomains have 2 dots (sub.example.com).
        if dot_count <= 1:
            return 1   # Legitimate
        elif dot_count == 2:
            return 0   # Suspicious
        return -1      # Likely Phishing


    def httpsCheck(self):
        if not self.parsed_url:
            return -1
        return 1 if self.parsed_url.scheme.lower() == "https" else -1

    def anchorURL(self):
        if not self.soup:
            return -1
        
        try:
            anchors = self.soup.find_all('a', href=True)
            total_anchors = len(anchors)
            if total_anchors == 0:
                return 1 # Low risk if no interactive links exist

            unsafe_count = 0
            for a in anchors:
                href = a['href'].lower()
                # Flag anchors that redirect to code blocks, blank states, or external domains
                if "#" in href or "javascript" in href or "mailto" in href:
                    unsafe_count += 1
                elif self.base_domain not in href and href.startswith(("http://", "https://")):
                    unsafe_count += 1

            percentage = (unsafe_count / total_anchors)
            if percentage < 0.33:
                return 1
            elif percentage < 0.66:
                return 0
            return -1
        except Exception:
            return -1

    def linksInScriptTags(self):
        if not self.soup:
            return -1
        try:
            total = 0
            matching = 0
            for link in self.soup.find_all('link', href=True):
                href = link['href']
                if self.base_domain in href or href.startswith("/"):
                    matching += 1
                total += 1
            for script in self.soup.find_all('script', src=True):
                src = script['src']
                if self.base_domain in src or src.startswith("/"):
                    matching += 1
                total += 1

            if total == 0:
                return 1

            percentage = (matching / total) * 100
            if percentage < 17.0:
                return 1
            elif percentage < 81.0:
                return 0
            return -1
        except Exception:
            return -1
    
    def websiteTraffic(self):
        """
        Utilizes the active Tranco Top 1M list API.
        Returns 1 if the domain is highly ranked, 0 if less popular, and -1 if missing.
        """
        if not self.base_domain:
            return -1
        try:
            api_url = f"https://tranco-list.eu/api/ranks/domain/{self.base_domain}"
            response = requests.get(api_url, timeout=3)
            # Corrected status check property
            if response.status_code == 200:
                data = response.json()
                ranks = data.get("ranks", [])
                if ranks:
                    current_rank = ranks[0].get("rank")
                    if current_rank and int(current_rank) <= 100000:
                        return 1
                    return 0
            return -1
        except Exception:
            return -1
    
    def getFeaturesDict(self):
        """
        Top Features to be parsed: 
        ['PrefixSuffix-', 'SubDomains', 'HTTPS', 
        'AnchorURL', 'LinksInScriptTags', 'WebsiteTraffic']
        """
        return {
            'PrefixSuffix-': self.prefixSuffix(),
            'SubDomains': self.subDomains(),
            'HTTPS': self.httpsCheck(),
            'AnchorURL': self.anchorURL(),
            'LinksInScriptTags': self.linksInScriptTags(),
            'WebsiteTraffic': self.websiteTraffic()
        }