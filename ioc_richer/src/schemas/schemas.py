import datetime as dt
from typing import List
from pydantic import BaseModel, Json


class BaseIoc(BaseModel):
    ioc_name: str = "Default ioc name"
    input_ioc: str
    input_ioc_type: str = ""
    ioc_ip_information: Json
    ioc_ip_blacklist: Json
    ioc_virustotal_ip: Json
    ioc_virustotal_ip_comments: Json
    ioc_virustotal_ip_related_domains: Json
    ioc_virustotal_file_behavior: Json
    ioc_virustotal_domain: Json
    ioc_virustotal_mitre: Json
    ioc_virustotal_hash: Json
    ioc_alienvault_domain: Json
    ioc_alienvault_hash: Json
    ioc_locations: Json
    ioc_domains: Json
    ioc_whois: Json
    ioc_isenriched: bool = False
    ioc_domain_reputations: Json


class Ioc(BaseIoc):
    id: int
    date_created: dt.datetime

    class Config:
        # orm_mode = True
        from_attributes = True
