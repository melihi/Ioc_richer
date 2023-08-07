import datetime as dt

import sqlalchemy

from ioc_richer.src.database.database import Base
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, JSON
from sqlalchemy import Column, String


class Ioc_model(Base):
    """Database model class .
    Args:
        Base () : declerative base .
    - ioc_name                examle:wannacry-ioc
    - input_ioc               ioc for enrichment process
    - input_ioc_type          type of input_ioc hash , ip , domain
    - ioc_ips                 found ip related with input_ioc
    - ioc_network             detailed network information.
    - ioc_hashes              found hashes related with input_ioc
    - ioc_process_name        found process names related with input_ioc
    - ioc_file_properties     found file details dlls , file type , sections,imports etc. related with input_ioc
    - ioc_av_results          antivirus results
    - ioc_locations           geo location information
    - ioc_domains             related domain names with input_ioc
    - ioc_whois               whois informations about domains
    - ioc_isenriched          boolean field for enrichment engine . if value is 0 enrichment engine automatically starts to enrichment.
    - ioc_ip_reputations      ip reputation informations from open source resources
    - ioc_domain_reputations  domain reputations from open source resources
    """

    # alembic
    # Column kisalt
    __tablename__ = "ioc_table"
    id = Column(sqlalchemy.Integer, primary_key=True, index=True)
    ioc_name = Column(String, index=True)
    input_ioc = Column(String, index=True)
    input_ioc_type = Column(String, index=True)
    ioc_ip_information = Column(JSONB, index=True)
    ioc_locations = Column(JSONB, index=True)
    ioc_domains = Column(JSONB, index=True)
    ioc_isenriched = Column(sqlalchemy.Boolean, index=True, default=False)
    ioc_whois = Column(JSONB, index=True)
    ioc_ip_blacklist = Column(JSONB, index=True)
    ioc_virustotal_ip = Column(JSONB, index=True)
    ioc_virustotal_ip_comments = Column(JSONB, index=True)
    ioc_virustotal_ip_related_domains = Column(JSONB, index=True)
    ioc_virustotal_mitre = Column(JSONB, index=True)
    ioc_virustotal_domain = Column(JSONB, index=True)
    ioc_virustotal_file_behavior = Column(JSONB, index=True)
    ioc_virustotal_hash = Column(JSONB, index=True)
    ioc_alienvault_domain = Column(JSONB, index=True)
    ioc_alienvault_hash = Column(JSONB, index=True)
    ioc_domain_reputations = Column(JSONB, index=True)
    date_created = Column(sqlalchemy.DateTime, default=dt.datetime.utcnow)
