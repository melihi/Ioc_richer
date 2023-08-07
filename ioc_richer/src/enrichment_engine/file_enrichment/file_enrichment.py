from ioc_richer.src.enrichment_engine.scan_services_enrichment.alienvault import (
    get_alienvault_file_hash,
)
from ioc_richer.src.enrichment_engine.scan_services_enrichment.virustotal import (
    get_virustotal_hash,get_virustotal_file_behavior,get_virustotal_mitre
)


def file_enrichment(hash: str):
    data = [
        get_alienvault_file_hash(hash),
        get_virustotal_hash(hash),
        get_virustotal_file_behavior(hash),
        get_virustotal_mitre(hash)
        
    ]
    return data
    
