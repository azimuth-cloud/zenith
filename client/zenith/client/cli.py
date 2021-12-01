import click

from .config import InitConfig, ConnectConfig
from .init import run as run_init
from .tunnel import create as run_connect


@click.group()
def main():
    """
    Zenith client entrypoint.
    """


@main.command()
@click.option(
    "--config",
    "config_path",
    type = click.Path(exists = True, file_okay = True, dir_okay = False),
    help = "Path to configuration file."
)
@click.option("--registrar-url", help = "URL of the Zenith registrar.")
@click.option(
    "--token",
    help = "Token issued by the Zenith registrar when the subdomain was reserved."
)
@click.option(
    "--ssh-identity-path",
    type = click.Path(exists = False),
    help = "The path of the SSH identity to use."
)
def init(config_path, **kwargs):
    """
    Initialise the Zenith client by associating the client's public key with a subdomain
    using the given token and registrar URL.

    An existing SSH identity can be provided, or one will be generated at the given path.
    """
    config_kwargs = { k: v for k, v in kwargs.items() if v is not None }
    config = InitConfig(_path = config_path, **config_kwargs)
    config.logging.apply()
    run_init(config)


@main.command()
@click.option(
    "--config",
    "config_path",
    type = click.Path(exists = True, file_okay = True, dir_okay = False),
    help = "Path to configuration file."
)
@click.option(
    "--run-as-user",
    type = int,
    help = "UID to switch to after reading configuration (when executed as root)."
)
@click.option(
    "--ssh-identity-path",
    type = click.Path(exists = True, file_okay = True, dir_okay = False),
    help = "The path to the SSH identity to use."
)
@click.option("--server-address", help = "The address of the target Zenith server.")
@click.option("--server-port", type = int, help = "The port of the target Zenith server.")
@click.option("--forward-to-host", help = "The address to forward tunnel traffic to.")
@click.option("--forward-to-port", type = int, help = "The port to forward tunnel traffic to.")
def connect(config_path, **kwargs):
    """
    Connect to a Zenith server and establish a secure tunnel.

    A limited set of configuration options are available as CLI options. For more
    sophisticated configurations, use environment variables or a configuration file.
    """
    config_kwargs = { k: v for k, v in kwargs.items() if v is not None }
    config = ConnectConfig(_path = config_path, **config_kwargs)
    config.logging.apply()
    run_connect(config)
