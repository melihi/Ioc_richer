from ioc_richer.src.enrichment_engine.scan_services_enrichment.alienvault import (
    get_alienvault_domain_info,
)
from ioc_richer.src.enrichment_engine.scan_services_enrichment.virustotal import (
    get_virustotal_domain,
)
from ioc_richer.src.http.request import *
from bs4 import BeautifulSoup
import json
import whois
import logging

URLVOID = "https://www.urlvoid.com/scan/{}/"


def domain_enrichment(domain: str):
    data = [
        query_whois(domain),
        get_alienvault_domain_info(domain),
        get_virustotal_domain(domain),
        query_blacklist(domain),
    ]
    return data


def query_whois(domain: str):
    try:
        w = whois.whois(domain)

        data = {"whois": w.text}

    except Exception as e:
        logging.warn("Whois failed : query.whous : ", e)
    return json.dumps(data)


def query_blacklist(domain: str):
    resp = get_request(URLVOID.format(domain), HEADERS)
    soup = BeautifulSoup(resp.text, "html.parser")

    data = {}
    tbody = soup.findAll("tbody")
    print(len(tbody))

    for row in tbody[1].find_all("tr"):
        columns = row.find_all("td")

        # engine = columns[0].text.strip()
        result = columns[1].text.strip()
        details = columns[2].find("a")["href"]

        # print(f"Engine: {engine}")
        data[result] = details

    return json.dumps(data)
