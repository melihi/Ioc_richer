from ioc_richer.src.http.request import get_request, HEADERS
from ioc_richer.config import GREYNOISE_APIKEY

URL = "https://api.greynoise.io/v3/community/{}"

HEADERS["accept"] = "application/json"

HEADERS["key"] = "fgVcYkiaghtkaWGLHUIAlWCCTWI5NBlUkaN9r8U3pHRNrQuMnaw4SEEZQPHutgdg"


def get_greynoise(ip: str):
    """Search in greynoise.io.

    Args:
        ip (str): ip address.
    """
    response = get_request.get(URL.format(ip), headers=HEADERS)
    if response.status_code == 200:
        response.text
