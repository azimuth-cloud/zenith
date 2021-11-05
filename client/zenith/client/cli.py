import functools
import json

import click

from .config import ClientConfig
from . import tunnel


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


@click.command()
@config_options(ClientConfig, exclude = {"logging", "ssh_executable"})
def main(config):
    """
    Starts a Zenith tunnel.
    """
    config.logging.apply()
    tunnel.create(config)
