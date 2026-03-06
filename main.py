from src.threat_intel.virustotal_client import VirusTotalClient
from src.processors.batch_processor import process_iocs, save_results_to_json
from src.utils.log_parser import parse_log_file, save_ips_to_file
import json

client = VirusTotalClient()
parsed_logs = parse_log_file(r"test.log")
print("Parsed logs:", parsed_logs)  
save_ips_to_file(parsed_logs, r"E:\IOC.txt" )
print("IOC file saved!")  
results = process_iocs(r"E:\IOC.txt", client)
save_results_to_json(results, r"E:\results.json")

