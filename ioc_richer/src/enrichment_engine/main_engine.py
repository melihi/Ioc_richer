from ioc_richer.src.crud.crud import *
from ioc_richer.src.enrichment_engine.ip_enrichment.ip_enrichment import ip_enrichment
from ioc_richer.src.enrichment_engine.domain_enrichment.domain_enrichment import (
    domain_enrichment,
)
from ioc_richer.src.enrichment_engine.file_enrichment.file_enrichment import (
    file_enrichment,
)
from ioc_richer.src.enrichment_engine.scan_services_enrichment.virustotal import *
from ioc_richer.src.enrichment_engine.scan_services_enrichment.alienvault import *
from ioc_richer.logger import setup_logger
import json

logger = setup_logger("enrichment", "enrichment.log")


def start_engine():
    data = read_data_enrichment()

    for fields in data:
        match fields.input_ioc_type:
            case "hash":
                enrich_hash(fields)
            case "ip":
                enrich_ip(fields)
            case "domain":
                enrich_domain(fields)


def enrich_ip(fields: Ioc_model):
    data = ip_enrichment(fields.input_ioc)
    if data[0] != "":
        update_data_enrichment(
            fields,
            (json.loads('{"ripe_net":' + data[0] + "}")),
            "ioc_ip_information",
            Ioc_model.ioc_ip_information,
        )

    if data[1] != None:
        update_data_enrichment(
            fields,
            (json.dumps("{'hurricane blacklist':" + str(data[1]) + "}")),
            "ioc_ip_blacklist",
            Ioc_model.ioc_ip_blacklist,
        )

    if data[2] != None:
        update_data_enrichment(
            fields,
            (json.loads(data[2])),
            "ioc_locations",
            Ioc_model.ioc_locations,
        )
    if data[3] != None:
        update_data_enrichment(
            fields,
            (json.dumps(json.loads(data[3]), separators=(",", ":"))),
            "ioc_virustotal_ip",
            Ioc_model.ioc_virustotal_ip,
        )
    """
    for i in  data[4]:
        update_data_enrichment(
            fields,
            json.dumps(i),
            "ioc_virustotal_ip_related_domains",
            Ioc_model.ioc_virustotal_ip_related_domains,
        )
        break
    """
    if data[5] != None:
        update_data_enrichment(
            fields,
            (json.dumps(json.loads(data[5]), separators=(",", ":"))),
            "ioc_virustotal_ip_comments",
            Ioc_model.ioc_virustotal_ip_comments,
        )
    update_data_enrichment(fields, True, "ioc_isenriched", Ioc_model.ioc_isenriched)


def enrich_domain(fields: Ioc_model):
    data = domain_enrichment(fields.input_ioc)

    update_data_enrichment(
        fields, json.loads(data[0]), "ioc_whois", Ioc_model.ioc_whois
    )
    update_data_enrichment(
        fields,
        json.loads(data[1]),
        "ioc_alienvault_domain",
        Ioc_model.ioc_alienvault_domain,
    )
    update_data_enrichment(
        fields,
        json.loads(data[2]),
        "ioc_virustotal_domain",
        Ioc_model.ioc_virustotal_domain,
    )
    update_data_enrichment(
        fields, json.loads(data[3]), "ioc_domain_reputations", Ioc_model.ioc_domain_reputations
    )

    update_data_enrichment(fields, True, "ioc_isenriched", Ioc_model.ioc_isenriched)


def enrich_hash(fields: Ioc_model):
    data = file_enrichment(fields.input_ioc)

    if data[0] != None:
        update_data_enrichment(
            fields,
            json.loads(data[0]),
            "ioc_alienvault_hash",
            Ioc_model.ioc_alienvault_hash,
        )

    update_data_enrichment(
        fields,
        json.loads((data[1])),
        "ioc_virustotal_hash",
        Ioc_model.ioc_virustotal_hash,
    )
    if data[2] != None:
        update_data_enrichment(
            fields,
            json.loads(data[2]),
            "ioc_virustotal_file_behavior",
            Ioc_model.ioc_virustotal_file_behavior,
        )
    """  if data[3] != None:
        update_data_enrichment(
            fields,
            json.loads(data[3]),
            "ioc_virustotal_mitre",
            Ioc_model.ioc_virustotal_mitre,
        ) """
    update_data_enrichment(fields, True, "ioc_isenriched", Ioc_model.ioc_isenriched)
