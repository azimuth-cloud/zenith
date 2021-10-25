import asyncio

import click

from .config import ClientConfig
from . import tunnel


@click.command()
@click.option("--config", type = click.Path(exists = True), help = "Path to configuration file")
def main(config):
    """
    Starts a Zenith tunnel.
    """
    config = ClientConfig(_path = config)
    config.logging.apply()
    tunnel.create(config)
