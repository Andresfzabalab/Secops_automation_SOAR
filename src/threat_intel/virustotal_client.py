from dataclasses import dataclass
from http.client import responses
from ipaddress import ip_address
import requests
import time
import base64
from  datetime import datetime


from ..config import api_key


class VirusTotalClient:
    def __init__(
        self,
        base_url="https://www.virustotal.com/api/v3",
        timeout=10,
        max_retries=3,
        retry_statuses=(429, 500, 502, 503, 504),
    ):
        if not api_key:
            raise ValueError("API key is required")
        if not base_url:
            raise ValueError("Base URL is required")

        self.api_key = api_key
        self.base_url = base_url
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_statuses = retry_statuses
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": self.api_key})

    def _make_request(self, method, endpoint, params=None, json=None):
        url = f"{self.base_url}/{endpoint}"
        last_error = "Unknown error"  

        for attempt in range(self.max_retries):
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    params=params,
                    json=json,
                    timeout=self.timeout,
                )

                if 200 <= response.status_code < 300:
                    return {
                        "success": True,
                        "status_code": response.status_code,
                        "data": response.json(),
                    }

                if response.status_code == 401:
                    raise ValueError("Authentication failed. Check your API key.")

                if response.status_code in self.retry_statuses:
                    delay = 2 ** attempt  
                    last_error = f"HTTP {response.status_code}"  
                    time.sleep(delay)
                    continue

                # Non-retryable HTTP error — return immediately
                return {
                    "success": False,
                    "status_code": response.status_code,
                    "error": response.text,
                }

            except requests.exceptions.RequestException as e:
                last_error = str(e) 
                delay = 2 ** attempt
                time.sleep(delay)
                continue

        return {
            "success": False,
            "status_code": None,
            "data": None,
            "error": f"Max retries ({self.max_retries}) exceeded. Last error: {last_error}",
        }
    
    def get_ip_report(self, ip: str) -> dict:
        result = self._make_request("GET", f"ip_addresses/{ip}")
        if result ["success"] is True:
            attributes = result["data"]["data"]["attributes"]
            return {
                "success": True,
                "ioc_type": "ip",
                "ioc_value": ip,
                "country": attributes.get("country", "Unknown"),
                "as_owner": attributes.get("as_owner", "Unknown"),
                "asn": attributes.get("asn","Unknown"),
                "reputation": attributes.get("reputation","Unknown"),
                "last_analysis_stats": attributes.get("last_analysis_stats","Unknown"),
            }
        else:
            return result
    
    
    def get_domain_report(self, domain: str) -> dict:
        result = self._make_request("GET", f"domains/{domain}")
        if result ["success"] is True:
            attributes = result["data"]["data"]["attributes"]
            return {
                "success": True,
                "ioc_type": "domains",
                "ioc_value": domain,
                "registrar": attributes["registrar"],
                "creation_date": datetime.fromtimestamp( attributes["creation_date"]).strftime("%Y-%m-%d"),
                "reputation": attributes["reputation"],
                "last_analysis_stats": attributes["last_analysis_stats"],
            }
        else:
            return result
    
    def get_hash_report(self, hash: str) -> dict:
        result = self._make_request("GET", f"files/{hash}")
        if result ["success"] is True:
            attributes = result["data"]["data"]["attributes"]
            return {
                "success": True,
                "ioc_type": "hash",
                "ioc_value": hash,
                "meaningful_name": attributes["meaningful_name"],
                "type_description": attributes["type_description"],
                "size": attributes["size"],
                "suggested_threat_label": attributes["popular_threat_classification"]["suggested_threat_label"],
                "last_analysis_stats": attributes["last_analysis_stats"],
            }
        else:
            return result
        
    def get_url_report(self, url: str) -> dict:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        result = self._make_request("GET", f"urls/{url_id}")
        if result ["success"] is True:
                attributes = result["data"]["data"]["attributes"]
                return {
                    "success": True,
                    "ioc_type": "urls",
                    "ioc_value": url,
                    "reputation": attributes["reputation"],
                    "last_analysis_stats": attributes["last_analysis_stats"],
                }
        else:
            return result

            
        
        
        