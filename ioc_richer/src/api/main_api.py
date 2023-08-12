from typing import List
import fastapi
from ioc_richer.src.database.database import *
from ioc_richer.src.schemas.schemas import Ioc, BaseIoc
from ioc_richer.src.crud.crud import *
from sqlalchemy.orm import Session
import json

# initialize Fastapi
APP = fastapi.FastAPI()
# create table in postgresql
add_tables()


@APP.get("/api/v1/ioc/all")
async def get_ioc(
    skip: int = 0, limit: int = 100, db: Session = fastapi.Depends(get_db)
):
    """
    Retrieve all ioc data in database.\n
    ## Args:
        skip : first item index.
        limit :  max returned data count.
    """
    iocs = get_all_ioc_service(db, skip=skip, limit=limit)

    return iocs


@APP.get("/api/v1/{ioc_data}", response_model=List[Ioc])
async def search_ioc(
    ioc_data: str, ioc_type: str, db: Session = fastapi.Depends(get_db)
):
    """
    Search ioc data in database.\n
    ## Args:
        ioc_data : search input.
        ioc_type : ip , domain , hash , name , enrichment.
    """
    data = search_ioc_service(db, ioc_data, ioc_type)
    return data


@APP.post("/api/v1/", response_model=Ioc)
async def create_ioc(ioc: BaseIoc, db: Session = fastapi.Depends(get_db)):
    """
    Create ioc data in database.\n
    ## Args:
        ioc : ioc_model.
    """

    model = create_ioc_service(db, ioc)
    return model


@APP.post("/api/v1/add", response_model=Ioc)
async def add_ioc(
    ioc_name: str, ioc: str, ioc_type: str, db: Session = fastapi.Depends(get_db)
):
    """
    Add ioc data  to database for enrichment.\n
    ## Args:
        ioc_name : name of ioc . apt36,attackLizard etc.
        ioc : google.com , 192.168.1.1 , 6aef6a546a8f46a83f
        ioc_type : domain , ip , hash
    """

    test = BaseIoc(
        ioc_name=ioc_name,
        input_ioc=ioc,
        input_ioc_type=ioc_type,
        ioc_domain_reputations=json.dumps("[]"),
        ioc_domains=json.dumps("[]"),
        ioc_ip_information=json.dumps("[]"),
        ioc_virustotal_ip=json.dumps("[]"),
        ioc_virustotal_ip_related_domains=json.dumps("[]"),
        ioc_virustotal_ip_comments=json.dumps("[]"),
        ioc_virustotal_file_behavior=json.dumps("[]"),
        ioc_virustotal_mitre=json.dumps("[]"),
        ioc_virustotal_hash=json.dumps("[]"),
        ioc_virustotal_domain=json.dumps("[]"),
        ioc_alienvault_hash=json.dumps("[]"),
        ioc_alienvault_domain=json.dumps("[]"),
        ioc_whois=json.dumps("[]"),
        ioc_file_behavior=json.dumps("[]"),
        ioc_locations=json.dumps("[]"),
        ioc_ip_blacklist=json.dumps("[]"),
        ioc_isenriched=False,
    )

    model = create_ioc_service(db, test)
    return model


@APP.get("/")
async def root():
    return {"message": "Welcome To Ioc enrichment Fastapi"}
