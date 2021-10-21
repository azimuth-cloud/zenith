import asyncio
import logging.config

import click

from .config import SyncConfig
from .main import run


@click.command()
@click.option("--config", type = click.Path(exists = True), help = "Path to configuration file")
def main(config):
    """
    Synchronises Zenith services from Consul with Kubernetes.
    """
    config = SyncConfig(_path = config)
    logging.config.dictConfig(config.logging)
    asyncio.run(run(config))
