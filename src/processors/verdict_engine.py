import re

def get_verdict(enriched_ioc: dict) -> dict:
    malicious = enriched_ioc["last_analysis_stats"]["malicious"]
    if malicious <= 2:
        verdict = "Clean"
    elif malicious <= 10:
        verdict = "Suspect"
    else:
        verdict = "Malicius"
    
    enriched_ioc["verdict"] = verdict
    return enriched_ioc

def apply_verdicts(results: list) -> list:
    results_with_verdict = []
    for analycis in results:
        verdict_result = get_verdict(analycis) 
        results_with_verdict.append(verdict_result)
    return results_with_verdict