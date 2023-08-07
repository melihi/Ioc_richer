import logging

import httpx

TIMEOUT = 30

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Referer": "http://www.google.com/",
}


def get_request(url: str, head: dict) -> httpx.Response:
    """http get request function.
    Args:
        url (str) : url address .
        head (dict) : headers dictionary .

    """
    try:
        with httpx.Client(
            headers=head, timeout=TIMEOUT, follow_redirects=True
        ) as client:
            response = client.get(url, follow_redirects=True)
    except httpx.HTTPError as e:
        logging.warn("Get request error " + str(e))
        return None
    return response


def post_request(url: str, data, head) -> httpx.Response:
    """http post request function.
    Args:
        url  : url address .
        head : headers dictionary .
        data  : body data  .

    """
    try:
        with httpx.Client(
            headers=head, timeout=TIMEOUT, follow_redirects=True
        ) as client:
            response = client.post(url, follow_redirects=True, json=data)
    except httpx.HTTPError as e:
        logging.warn("post request error " + str(e))
        return

    return response
