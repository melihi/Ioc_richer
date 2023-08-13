from ioc_richer.src.http.request import get_request, HEADERS, httpx
import logging

THREATMINER_HOST = "https://api.threatminer.org/v2/host.php?q={}&rt=4"
THREATMINER_DOMAIN = "https://api.threatminer.org/v2/domain.php?q={}&rt=2"
THREATMINER_REPORT = "https://api.threatminer.org/v2/domain.php?q={}&rt=6"
THREATMINER_IP_RELATED_DOMAINS = "https://api.threatminer.org/v2/host.php?q={}&rt=2"
THREATMINER_AV_DETECTION = "https://api.threatminer.org/v2/sample.php?q={}&rt=6"


def get_threatminer_av_detect(hash: str) -> str:
    """Threatminer av detection results.

    Args:
        hash (str): file hash.

    """
    try:
        resp = get_request(THREATMINER_AV_DETECTION.format(hash), HEADERS)
        if resp.status_code != 200:
            logging.warn("threatminer.org http status code not 200", resp.status_code)
            return
        return resp.text

    except Exception as err:
        logging.warn(f"get_threatminer_av_detect Error: {err}")


def get_threatminer_host(ip: str) -> str:
    """Threatminer ip information.

    Args:
        ip (str): ip adress.

    Returns:
        str: _description_
    """
    try:
        resp = get_request(THREATMINER_HOST.format(ip), HEADERS)
        if resp.status_code != 200:
            logging.warn("threatminer.org http status code not 200", resp.status_code)
            return
        return resp.text

    except Exception as err:
        logging.warn(f"get_threatminer_host Error: {err}")


def get_threatminer_domain(domain: str) -> str:
    """Threatminer domain.

    Args:
        domain (str): domain name.

    """

    try:
        resp = get_request(THREATMINER_DOMAIN.format(domain), HEADERS)
        if resp.status_code != 200:
            logging.warn("threatminer.org http status code not 200", resp.status_code)
            return
        return resp.text

    except Exception as err:
        logging.warn(f"get_threatminer_domain Error: {err}")


def get_threatminer_report(domain: str) -> str:
    """Threatminer domain report.

    Args:
        domain (str): domain name.


    """

    try:
        resp = get_request(THREATMINER_REPORT.format(domain), HEADERS)
        if resp.status_code != 200:
            logging.warn("threatminer.org http status code not 200", resp.status_code)
            return
        return resp.text

    except Exception as err:
        logging.warn(f"get_threatminer_report Error: {err}")


def get_threatminer_ip_related(ip: str) -> str:
    """Threatminer ip related domain data.

    Args:
        ip (str): ip adress


    """

    try:
        resp = get_request(THREATMINER_IP_RELATED_DOMAINS.format(ip), HEADERS)
        if resp.status_code != 200:
            logging.warn("threatminer.org http status code not 200", resp.status_code)
            return
        return resp.text

    except Exception as err:
        logging.warn(f"get_threatminer_ip_related Error: {err}")
