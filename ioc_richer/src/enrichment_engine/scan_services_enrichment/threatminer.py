from ioc_richer.src.http.request import get_request, HEADERS
import logging

THREATMINER_HOST = "https://api.threatminer.org/v2/host.php?q={}&rt=4"
THREATMINER_DOMAIN = "https://api.threatminer.org/v2/domain.php?q={}&rt=2"
THREATMINER_REPORT = "https://api.threatminer.org/v2/domain.php?q={}&rt=6"
THREATMINER_IP_RELATED_DOMAINS = "https://api.threatminer.org/v2/host.php?q={}&rt=2"
THREATMINER_AV_DETECTION = "https://api.threatminer.org/v2/sample.php?q={}&rt=6"


def get_threatminer_av_detect(hash: str):
    resp = get_request(THREATMINER_AV_DETECTION.format(hash), HEADERS)

    if resp.status_code != 200:
        logging.warn("threatminer.org http status code not 200", resp.status_code)
        return
    return resp.text


def get_threatminer_host(ip: str):
    resp = get_request(THREATMINER_HOST.format(ip), HEADERS)

    if resp.status_code != 200:
        logging.warn("threatminer.org http status code not 200", resp.status_code)
        return
    return resp.text


def get_threatminer_domain(domain: str):
    resp = get_request(THREATMINER_DOMAIN.format(domain), HEADERS)

    if resp.status_code != 200:
        logging.warn("threatminer.org http status code not 200", resp.status_code)
        return
    return resp.text


def get_threatminer_report(domain: str):
    resp = get_request(THREATMINER_REPORT.format(domain), HEADERS)

    if resp.status_code != 200:
        logging.warn("threatminer.org http status code not 200", resp.status_code)
        return
    return resp.text


def get_threatminer_ip_related(ip: str):
    resp = get_request(THREATMINER_IP_RELATED_DOMAINS.format(ip), HEADERS)

    if resp.status_code != 200:
        logging.warn("threatminer.org http status code not 200", resp.status_code)
        return
    return resp.text
