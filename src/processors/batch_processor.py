import os
import re
import time
import json

def read_iocs_from_file(file_path: str) -> list:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    iocs = []
    with open(file_path, "r") as file:
        lines = file.readlines()
        for line in lines:
            clean_line = line.strip()  
            if clean_line:
                iocs.append(clean_line)
    
    return iocs

def detect_ioc_type(value: str) -> str:
    if value.startswith(("http://", "https://")):
        return "URL"
    elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
        return "IP"
    elif len(value) in [32, 40, 64] and value.isalnum():
        return "hash"
    elif re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value):
        return "Domain"
    else:
        return "unknown"

def process_iocs(file_path: str, client) -> list:
    IOC = []
    read = read_iocs_from_file(file_path)
    sender = 0
    for lines in read:
        detect = detect_ioc_type(lines)
        if detect == "IP":
            result = client.get_ip_report(lines)
        elif detect == "URL":
            result = client.get_url_report(lines)
        elif detect == "hash":
            result = client.get_hash_report(lines)
        else:
            result = client.get_domain_report(lines)
        if result["success"] is True:
            sender +=1
            if sender == 4:
                time.sleep(60)
                sender = 0
        IOC.append(result)
            
    return IOC

def save_results_to_json(results: list, output_path: str) -> None:
    if not results:
        raise ValueError("The list is empty verify is all things are correct")
    with open(output_path, "w") as file:
        json.dump(results, file, indent=2)