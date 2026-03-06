import re

def get_verdict(enriched_ioc: dict) -> dict:
    stats = enriched_ioc.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    if malicious <= 2:
        verdict = "CLEAN"
    elif malicious <= 10:
        verdict = "SUSPICIOUS"
    else:
        verdict = "MALICIOUS"
    
    enriched_ioc["verdict"] = verdict
    return enriched_ioc

def apply_verdicts(results: list) -> list:
    results_with_verdict = []
    for analycis in results:
        verdict_result = get_verdict(analycis) 
        results_with_verdict.append(verdict_result)
    return results_with_verdict