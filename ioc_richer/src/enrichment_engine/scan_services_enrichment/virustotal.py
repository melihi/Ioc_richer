from ioc_richer.src.http.request import *
from ioc_richer.config import *
import json
import logging


DOMAINS = "https://www.virustotal.com/api/v3/domains/"
FILES = "https://www.virustotal.com/api/v3/files/"
IP = "https://www.virustotal.com/api/v3/ip_addresses/"
IP_COMMENT = "https://www.virustotal.com/api/v3/ip_addresses/{}/comments"
IP_RELATION = "https://www.virustotal.com/api/v3/ip_addresses/{}/resolutions?limit=40"
FILE_BEHAVIOR = "https://www.virustotal.com/api/v3/files/{}/behaviour_summary"
MITRE = "https://www.virustotal.com/api/v3/files/{}/behaviour_mitre_trees"


HEADERS["x-apikey"] = VIRUSTOTAL_APIKEY


def get_virustotal_domain(domain: str):
    """
    # curl --request GET \
    # --url https://www.virustotal.com/api/v3/domains/{domain} \
    # --HEADERSer 'x-apikey: <your API key>'
    """
    try:
        resp = get_request(DOMAINS + domain, HEADERS)
        if resp.status_code == 200:
            return resp.text

    except Exception as err:
        logging.warn(f"get_virustotal_domain Error: {err}")


def get_virustotal_hash(hash: str):
    """
    # curl --request GET \
    #  --url https://www.virustotal.com/api/v3/files/{id} \
    #  --HEADERSer 'x-apikey: <your API key>'
    """
    try:
        resp = get_request(FILES + hash, HEADERS)

        if resp.status_code == 200:
            return resp.text
        else:
            logging.warn("Virustotal returned not http 200 . get_virustotal_hash ")

    except Exception as err:
        logging.warn(f"get_virustotal_hash Error: {err}")


def get_virustotal_ip(ip: str) -> str:
    """ curl --request GET \
    # --url https://www.virustotal.com/api/v3/ip_addresses/{ip} \
    # --HEADERSer 'x-apikey: <your API key>'
    # ip comments
    """
    try:
        resp = get_request(IP + ip, HEADERS)
        if resp.status_code == 200:
            return resp.text
        else:
            logging.warn("Virustotal returned not http 200 . get_virustotal_ip ")

    except Exception as err:
        logging.warn(f"get_virustotal_ip Error: {err}")


def get_virustotal_ipcomment(ip: str) -> str:
    """
    # curl --request GET \
    # --url https://www.virustotal.com/api/v3/ip_addresses/{ip}/comments \
    # --HEADERSer 'x-apikey: <your API key>'
    """
    try:
        resp = get_request(IP.format(ip), HEADERS)
        if resp.status_code == 200:
            return resp.text
        else:
            logging.warn("Virustotal returned not http 200 . get_virustotal_ipcomment ")

    except Exception as err:
        logging.warn(f"get_virustotal_ipcomment Error: {err}")


def get_virustotal_ip_related_domains(ip: str) -> list:
    """
    curl --request GET \
     --url https://www.virustotal.com/api/v3/ip_addresses/{id}/{relationship} \
     --HEADERSer 'x-apikey: <your API key>'
    """
    next_page = IP_RELATION.format(ip)
    datas = []
    try:
        while next_page != None:
            resp = get_request(next_page, HEADERS)
            if resp.status_code == 200:
                json_data = json.loads(resp.text)
                datas.append(resp.text)
                if "next" in json_data["links"]:
                    next_url = json_data["links"]["next"]
                    next_page = next_url
                else:
                    next_page = None
            else:
                logging.warn(
                    "Virustotal returned not http 200 . get_virustotal_ip_related_domains"
                )
                break
        return datas

    except Exception as err:
        logging.warn(f"get_virustotal_ip_related_domains Error: {err}")


def get_virustotal_file_behavior(hash: str):
    """
   curl --request GET \
  --url https://www.virustotal.com/api/v3/files/{id}/behaviour_summary \
  --HEADERSer 'x-apikey: <your API key>'
    """
    try:
        resp = get_request(FILE_BEHAVIOR.format(hash), HEADERS)
        if resp.status_code == 200:
            return resp.text
        else:
            logging.warn(
                "Virustotal returned not http 200 . get_virustotal_file_behavior "
            )

    except Exception as err:
        logging.warn(f"get_virustotal_file_behavior Error: {err}")


def get_virustotal_mitre(hash: str) -> str:
    """
    curl --request GET \
    --url https://www.virustotal.com/api/v3/files/{id}/behaviour_mitre_trees \
    --HEADERSer 'x-apikey: <your API key>'
    """
    try:
        resp = get_request(MITRE.format(hash), HEADERS)
        if resp.status_code == 200:
            return resp.text
        else:
            logging.warn("Virustotal returned not http 200 . get_virustotal_mitre ")

    except Exception as err:
        logging.warn(f"get_virustotal_mitre Error: {err}")
