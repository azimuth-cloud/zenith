import click
import functools

from .config import ClientConfig
from . import tunnel


def config_options(config_cls, exclude = None):
    """
    Returns a decorator that adds command line options for the fields of a Pydantic model.
    """
    exclude = exclude or {}
    # Convert to kebab-case and prepend with "--"
    options = [
        (f"--{k.replace('_', '-')}", f.field_info.description)
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


@click.command()
@config_options(ClientConfig, exclude = {"logging", "ssh_executable"})
def main(config):
    """
    Starts a Zenith tunnel.
    """
    config.logging.apply()
    tunnel.create(config)
