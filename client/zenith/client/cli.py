import functools
import json

import click

from .config import BootstrapConfig, ConnectConfig
from .bootstrap import run as run_bootstrap
from .tunnel import create as run_connect


class JsonStringParamType(click.ParamType):
    """
    Parameter type for click that decodes the received string as JSON.
    """
    name = "json-string"

    def convert(self, value, param, ctx):
        if not isinstance(value, str):
            self.fail("given value should be a string")
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            self.fail(f"{value!r} is not a valid JSON document", param, ctx)


def config_options(config_cls, exclude = None):
    """
    Returns a decorator that adds command line options for the fields of a Pydantic model.
    """
    exclude = exclude or {}
    options = [
        (
            # Convert to kebab-case and prepend with "--"
            f"--{k.replace('_', '-')}",
            f.field_info.description,
            # For complex types, use the json-string type
            JsonStringParamType() if f.is_complex() else str
        )
        for k, f in config_cls.__fields__.items()
        if k not in exclude
    ]
    # Sorting the options in reverse means they come out in order when the reduction is applied
    options.sort(reverse = True)
    def decorator(func):
        # Filter the supplied options that are passed to the underlying function
        @functools.wraps(func)
        def decorated(config, **kwargs):
            kwargs = { k: v for k, v in kwargs.items() if v }
            config_obj = config_cls(_path = config, **kwargs)
            return func(config_obj)
        decorated = functools.reduce(
            lambda f, opt: click.option(
                opt[0],
                type = opt[2],
                # This suppresses the "TEXT" in help output
                metavar = "",
                help = opt[1] or ""
            )(f),
            options,
            decorated
        )
        # Finish with a decorator for specifying a config file, which will appear first
        # in the argument list
        return click.option(
            "--config",
            type = click.Path(exists = True),
            metavar = "",
            help = "Path to configuration file"
        )(decorated)
    return decorator


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
def bootstrap(config_path, **kwargs):
    """
    Bootstrap the Zenith client by associating the client's public key with a subdomain
    using the given token and registrar URL.

    An existing SSH identity can be provided, or one will be generated at the given path.
    """
    config_kwargs = { k: v for k, v in kwargs.items() if v is not None }
    config = BootstrapConfig(_path = config_path, **config_kwargs)
    config.logging.apply()
    run_bootstrap(config)


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
