from ioc_richer.src.http.request import post_request, HEADERS, httpx
import json
import logging

THREATFOX_SEARCH = "https://threatfox-api.abuse.ch/api/v1/"


def search_threatfox(data: str):
    """Search in threatfox-api.abuse.ch.

    Args:
        data (str): ip,domain,str


    """
    # curl -X POST https://threatfox-api.abuse.ch/api/v1/ -d '{ "query": "search_ioc", "search_term": "139.180.203.104" }'
    try:
        jsonstr = {"query": "search_ioc", "search_term": "{}".format(data)}
        response = post_request(
            THREATFOX_SEARCH,
            jsonstr,
            HEADERS,
        )
        if response.status_code == 200:
            return response.text

    except Exception as err:
        logging.warn(f"search_threatfox Error: {err}")
