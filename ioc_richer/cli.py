import click
import uvicorn
from ioc_richer.src.enrichment_engine.main_engine import *
from apscheduler.schedulers.blocking import BlockingScheduler


@click.group()
def ioc_richer():
    click.echo("Ioc richer")


@ioc_richer.command()
@click.option("--api", "-a", is_flag=True, help="Run api service")
@click.option("--crawler", "-c", is_flag=True, help="Run crawler service")
def manage(api: bool, crawler: bool):
    """Ioc richer manage cli"""
    if api:
        uvicorn.run(
            "ioc_richer.src.api.main_api:APP", host="0.0.0.0", port=8000, reload=True
        )
    elif crawler:
        
        scheduler = BlockingScheduler(daemon=True)
        scheduler.add_job(
            start_engine,
            "interval",
            seconds=10,
            max_instances=1,
        )

        scheduler.start()
