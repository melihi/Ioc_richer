from ioc_richer.src.enrichment_engine.scan_services_enrichment.alienvault import (
    get_alienvault_file_hash,
)
from ioc_richer.src.enrichment_engine.scan_services_enrichment.virustotal import (
    get_virustotal_hash,
    get_virustotal_file_behavior,
    get_virustotal_mitre,
)
from ioc_richer.src.enrichment_engine.scan_services_enrichment.malshare import (
    get_malshare,
)
from ioc_richer.src.enrichment_engine.scan_services_enrichment.threatfox import (
    search_threatfox,
)
from ioc_richer.src.enrichment_engine.scan_services_enrichment.malwarebazaar import (
    search_malwarebazaar,
)
from ioc_richer.src.enrichment_engine.scan_services_enrichment.malshare import (
    get_malshare,
)
from ioc_richer.src.enrichment_engine.scan_services_enrichment.threatminer import (
    get_threatminer_av_detect,
)


def file_enrichment(hash: str):
    data = [
        get_alienvault_file_hash(hash),
        get_virustotal_hash(hash),
        get_virustotal_file_behavior(hash),
        get_virustotal_mitre(hash),
        get_malshare(hash),
        search_threatfox(hash),
        search_malwarebazaar(hash),
        get_threatminer_av_detect(hash),
    ]
    return data
