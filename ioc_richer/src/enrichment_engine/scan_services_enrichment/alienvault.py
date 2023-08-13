from ioc_richer.src.http.request import *
from ioc_richer.config import ALIENVAULT_APIKEY
import json

SEARCH_FILE_HASH = "https://otx.alienvault.com/api/v1/indicator/file/{}"
SEARCH_DOMAIN = "https://otx.alienvault.com/api/v1/indicators/domain/{}/general"
HEADERS["X-OTX-API-KEY"] = ALIENVAULT_APIKEY


def get_alienvault_file_hash(hash: str):
    # curl https://otx.alienvault.com/api/v1/indicators/file/6c5360d41bd2b14b1565f5b18e5c203cf512e493/analysis -H "X-OTX-API-KEY: e3d7528d05eb4fb14392b5650101a33b9ac3de844d42ab8718438f4894d8526c"
    try:
        resp = get_request(SEARCH_FILE_HASH.format(hash), HEADERS)

        if resp.status_code == 200:
            return resp.text
        else:
            logging.warn("Virustotal returned not http 200 . get_virustotal_hash ")
    except Exception as err:
        logging.warn(f"get_alienvault_file_hash Error: {err}")


def get_alienvault_domain_info(domain: str):
    try:
        resp = get_request(SEARCH_DOMAIN.format(domain), HEADERS)
        if resp.status_code == 200:
            return resp.text
        else:
            logging.warn("Virustotal returned not http 200 . search_domain_info ")
    except Exception as err:
        logging.warn(f"get_alienvault_domain_info Error: {err}")
