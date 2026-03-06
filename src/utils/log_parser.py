import re
import os
from src.processors.batch_processor import detect_ioc_type




def parse_syslog_line(log: str) -> dict:
    parts = log.split() 
    timestamp = " ".join(parts[0:3])
    hostname = parts[3]
    service = parts[4].split("[")[0]
    for word in parts:
        ioc_type= detect_ioc_type(word)
        if ioc_type != "unknown":
            return{
                    "timestamp": timestamp,
                    "hostname": hostname,
                    "service": service,
                    "ioc_value": word,
                    "ioc_type": ioc_type,
        }


def parse_log_file(file: str) -> list:
    if not os.path.exists(file):
        raise FileNotFoundError(f"File not found: {file}")
    IOC_file = []
    with open(file, "r") as f:
        lines = f.readlines()
        for line in lines:
            parser = parse_syslog_line(line)
            if parser is None:
                continue
            else:
                IOC_file.append(parser)
    return IOC_file

def save_ips_to_file(parsed_logs: list, output_path: str) -> None:
    with open(output_path, "w") as f:
        for ip in parsed_logs:
            f.write(ip ["ioc_value"] + "\n") 