from ioc_richer.src.http.request import post_request, HEADERS


THREATFOX_SEARCH = "https://threatfox-api.abuse.ch/api/v1/"


def search_threatfox(data: str):
    """Search in threatfox-api.abuse.ch.

    Args:
        data (str): ip,domain,str


    """
    # curl -X POST https://threatfox-api.abuse.ch/api/v1/ -d '{ "query": "search_ioc", "search_term": "139.180.203.104" }'
    response = post_request.get(
        THREATFOX_SEARCH.format(THREATFOX_SEARCH),
        '{ "query": "search_ioc", "search_term": "{}" }'.format(data),
        HEADERS,
    )
    if response.status_code == 200:
        return response.text
