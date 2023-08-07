from ioc_richer.src.database.database import *

from sqlalchemy.orm import Session
from typing import List
from ioc_richer.src.models.models import Ioc_model
import logging
from sqlalchemy import update


def get_all_ioc_service(db: Session, skip: int = 0, limit: int = 100):
    return db.query(Ioc_model).offset(skip).limit(limit).all()


def search_ioc_service(db: Session, ioc_data: str = "", ioc_type: str = ""):
    """Search ioc
    Args:
        db: Session.
        ioc_data: search keyword
        ioc_type: ip,domain,hash,name,enrichment"""
    match ioc_type:
        case "ip":
            return (
                db.query(Ioc_model)
                .filter(Ioc_model.ioc_ip_information.any(ioc_data))
                .all()
            )
        case "domain":
            return db.query(Ioc_model).filter(Ioc_model.ioc_domains.any(ioc_data)).all()
        case "hash":
            return db.query(Ioc_model).filter(Ioc_model.ioc_hashes.any(ioc_data)).all()
        case "name":
            return (
                db.query(Ioc_model)
                .filter(Ioc_model.ioc_name.like(f"%{ioc_data}%"))
                .all()
            )
        case "enrichment":
            return (
                db.query(Ioc_model).filter(Ioc_model.ioc_isenriched == (ioc_data)).all()
            )
        case _:
            return {"message": "Unmatched ioc_type"}

    # query = db.query(Ioc_model).join(Ioc_model.ioc_type).filter_by(**test).all()
    # db.query(Ioc_model).filter(Ioc_model.test[ioc_type].any(ioc_data)).all()


def create_ioc_service(db: Session, ioc: Ioc_model):
    """Create ioc"""
    model = Ioc_model(**ioc.dict())
    db.add(model)
    db.commit()
    db.refresh(model)
    return model


def read_data_enrichment():
    """Read data which has ioc_isenriched == false ."""

    session = SessionLocal()

    return session.query(Ioc_model).filter(Ioc_model.ioc_isenriched == False).all()


def update_data_enrichment(model: Ioc_model, data, column_name: str, model_field):
    session = SessionLocal()
    try:
        query = (
            session.query(Ioc_model)
            .filter(Ioc_model.id == model.id)
            .update({column_name: data})#  model_field + data
        )

        # db.session.commit()
        # session.query(Ioc_model).filter(Ioc_model.id == model.id).update(
        #    {"ioc_ips": Ioc_model.ioc_ips + data}
        # )

        session.commit()
    except Exception as e:
        logging.warn("Insert crawler data failed :", e)
