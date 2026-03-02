import requests
import time
import backoff


class VirusTotalClient:
    def __init__(self, api_key, base_url="https://www.virustotal.com/api/v3", timeout=10, max_retries=3,retry_statuses = (429, 500, 502, 503, 504)):
        if not api_key:
            raise ValueError("API key is required")
        if not base_url:
            raise ValueError("Base URL is required")
        self.api_key = api_key
        self.base_url = base_url
        self.timeout = timeout
        self.headers = {"x-apikey": self.api_key}
        self.max_retries = max_retries
        self.retry_statuses = retry_statuses
        self.session = requests.Session()
        self.session.headers.update(self.headers)
    
   
    def _make_request(self, method, endpoint, params=None, json=None):
        url = f"{self.base_url}/{endpoint}"
        
        for attempt in range (self.max_retries):
            try:
                response = self.session.request(
                    method = method,
                    url = url,
                    params = params,
                    json = json,
                    timeout = self.timeout,
                )

                #Success case
                if 200 <= response.status_code < 300:
                    return{
                        "success": True,
                        "status_code": response.status_code,
                        "data": response.json(),
                    }
                
                if response.status_code == 401:
                    raise ValueError("Authentication failed. Check API key.")
                
                #Retryable HTTP errors
                if response.status_code in self.retry_statuses:
                    dealy = 2 ** attempt
                    time.sleep(delay)
                    continue
                
                #Non-retryable HTTP error
                return {
                    "success": False,
                    "status_code": response.status_code,
                    "error": response.text,
                }
                
            except requests.exceptions.RequestException as e:
                delay = 2 ** attempt
                time.sleep(delay)
                continue
        
        return {
            "success": False,
            "status_code": None,
            "data": None,
            "error": f"Max retries ({self.max_retries}) exceeded. Last error: {e}",
        }
    