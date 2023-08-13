from ioc_richer.src.http.request import *
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
from ioc_richer.src.enrichment_engine.scan_services_enrichment.virustotal import (
    get_virustotal_ip,
    get_virustotal_ip_related_domains,
    get_virustotal_ipcomment,
)
from ioc_richer.src.enrichment_engine.scan_services_enrichment.greynoise import (
    get_greynoise,
)
from ioc_richer.src.enrichment_engine.scan_services_enrichment.threatfox import (
    search_threatfox,
)
from ioc_richer.src.enrichment_engine.scan_services_enrichment.threatminer import (
    get_threatminer_host,
    get_threatminer_ip_related,
)
import json

RIPE_NET = "https://rdap.db.ripe.net/ip/{}"
HURRICANE = "https://bgp.he.net/ip/"
GEOLOCATION = "https://www.geolocation.com/?ip={}#ipresult"


def ip_enrichment(ip: str):
    """return all ip enrichment data as dict.

    Args:
        ip (str): ip adress

    Returns:
        data = {
        "get_ripe_net": get_ripe_net(ip),
        "get_hurricane": get_hurricane(ip),
        "get_geolocation": get_geolocation(ip),
        "get_virustotal_ip": get_virustotal_ip(ip),
        "get_virustotal_ip_related_domains": get_virustotal_ip_related_domains(ip),
        "get_virustotal_ipcomment": get_virustotal_ipcomment(ip),
         }
    """

    data = [
        get_ripe_net(ip),
        get_hurricane(ip),
        get_geolocation(ip),
        get_virustotal_ip(ip),
        get_virustotal_ip_related_domains(ip),
        get_virustotal_ipcomment(ip),
        get_greynoise(ip),
        search_threatfox(ip),
        get_threatminer_host(ip),
        get_threatminer_ip_related(ip),
    ]
    return data


def get_ripe_net(ip: str) -> str:
    """get ip informarion from ripe.net
    # https://rdap.db.ripe.net/ip/151.250.252.196

    Returns:
        str: httpx text
    """
    try:
        resp = get_request(RIPE_NET.format(ip), HEADERS)

        if resp.status_code != 200:
            logging.warn("Ripe.net http status code not 200", resp.status_code)
            return
        return resp.text

    except Exception as err:
        logging.warn(f"get_ripe_net Error: {err}")


def get_hurricane(ip: str) -> dict:
    # https://bgp.he.net/ip/151.250.252.195#_rbl
    # https://rdap.db.ripe.net/ip/151.250.252.196
    """Get list of RBL from hurricane electric .
    - https://bgp.he.net/ip/151.250.252.195#_rbl
    Args:
        ip: ip adress of target .
    Returns:
        dict: ip database service : pass | fail
    """

    data = {}
    try:
        with sync_playwright() as pw:
            # create browser instance
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(viewport={"width": 1920, "height": 1080})
            page = context.new_page()

            # rbldata
            lines = []
            page.goto(HURRICANE + ip + "#_rbl")
            page.wait_for_timeout(3000)
            a = page.locator('div[id="rbldata"]')
            try:
                for box in a.element_handles():
                    test = box.query_selector('div[class="rbllisted"]').inner_text()

                    lines = box.inner_text().split("\n")
                i = 0
                for _ in lines:
                    if i + 1 >= len(lines):
                        break
                    data[lines[i + 1]] = lines[i + 2]
                    i += 2
            except Exception as e:
                logging.warn("Hurricane data crawl failed ", e)
            return data

    except Exception as err:
        logging.warn(f"get_hurricane Error: {err}")


def get_geolocation(ip: str) -> str:
    """https://www.geolocation.com/?ip=151.250.252.195#ipresult

    Args:
        ip (str): ip adress

    Returns:
        str: return json text
    """
    try:
        resp = get_request(GEOLOCATION.format(ip), HEADERS)

        if resp.status_code != 200:
            logging.warn("geolocation.com data crawl failed http status not 200 ")
            return
        soup = BeautifulSoup(resp.text, "html.parser")

        json_tag = soup.findAll("code", {"class": "language-json"})
        # print(json_tag[1].get_text())
        return json_tag[1].get_text()

    except Exception as err:
        logging.warn(f"get_geolocation Error: {err}")
