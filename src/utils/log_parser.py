import re
import os


log1 = "Oct 10 13:55:36 webserver01 sshd[4521]: Failed password from 45.33.32.156"

log2 = "Oct 10 13:55:36 webserver01 systemd[1]: Started Daily apt upgrade"

def parse_syslog_line(log: str) -> dict:
    parts = log.split() 
    timestamp = " ".join(parts[0:3])
    hostname = parts[3]
    service = parts[4].split("[")[0]
    match =  re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", log)
    ip = match.group() if match else None
    return{
        "timestamp": timestamp,
        "hostname": hostname,
        "service": service,
        "ip_address": ip,
    }


print( parse_syslog_line(log1), sep="\n")
print( parse_syslog_line(log2), sep="\n")

def parse_log_file(file: str) -> list:
    if not os.path.exists(file):
        raise FileNotFoundError(f"File not found: {file}")
    IOC_file = []
    with open(file, "r") as f:
        lines = f.readlines()
        for line in lines:
            parser = parse_syslog_line(line)
            if parser["ip_address"] is None:
                continue
            else:
                IOC_file.append(parser)
    return IOC_file

def save_ips_to_file(parsed_logs: list, output_path: str) -> None:
    with open(output_path, "w") as f:
        for ip in parsed_logs:
            f.write(ip ["ip_address"] + "\n") 