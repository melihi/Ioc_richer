from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


from ioc_richer.config import HOST, USERNAME, PASSWORD


DATABASE_URL = "postgresql://" + USERNAME + ":" + PASSWORD + "@" + HOST + "/ioc_db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def add_tables():
    """
    Creates database tables .
    """
    return Base.metadata.create_all(bind=engine)



