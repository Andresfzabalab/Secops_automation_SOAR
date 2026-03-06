from src.threat_intel.virustotal_client import VirusTotalClient
from src.processors.batch_processor import process_iocs, save_results_to_json
from src.utils.log_parser import parse_log_file, save_ips_to_file
from src.processors.verdict_engine import apply_verdicts
import json

client = VirusTotalClient()
parsed_logs = parse_log_file(r"test.log")
save_ips_to_file(parsed_logs, r"E:\IOC.txt" )
results = process_iocs(r"E:\IOC.txt", client)
final_results = apply_verdicts(results)
save_results_to_json(final_results, r"E:\results.json")

