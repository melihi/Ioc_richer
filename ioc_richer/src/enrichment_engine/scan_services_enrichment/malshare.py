from ioc_richer.src.http.request import get_request, HEADERS, httpx
from ioc_richer.config import MALSHARE_APIKEY
import logging

MALSHARE = "https://www.malshare.com/api.php?api_key={}&action=details&hash={}"


def get_malshare(hash: str):
    """Search in malshare.com.

    Args:
        hash (str): hash of file.
    """
    try:
        response = get_request(MALSHARE.format(MALSHARE_APIKEY, hash), HEADERS)
        if response.status_code == 200:
            return response.text

    except Exception as err:
        logging.warn(f"get_malshare Error: {err}")
