from ioc_richer.src.http.request import get_request, HEADERS
from ioc_richer.config import MALSHARE_APIKEY


MALSHARE = "https://www.malshare.com/api.php?api_key={}&action=details&hash={}"


def get_malshare(hash: str):
    """Search in malshare.com.

    Args:
        hash (str): hash of file.
    """    
    response = get_request.get(MALSHARE.format(MALSHARE_APIKEY, hash), headers=HEADERS)
    if response.status_code == 200:
        return response.text
