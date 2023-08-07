from dynaconf import Dynaconf
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
settings = Dynaconf(
    load_dotenv=True,
    dotenv_path=ROOT_DIR.joinpath("envs", ".env"),
    envvar_prefix_for_dynaconf=False,
)
HOST = settings("HOST")
USERNAME = settings("USERNAME")
PASSWORD = settings("PASSWORD")
ALIENVAULT_APIKEY = settings("alienvault_apikey")
VIRUSTOTAL_APIKEY = settings("virustotal_apikey")