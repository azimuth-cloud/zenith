from importlib.metadata import entry_points

import click


ZENITH_SUBCOMMANDS_ENTRY_POINT = "zenith.cli.subcommands"


@click.group()
def app():
    """
    Zenith command line interface.
    """


def main():
    """
    Add the commands from the entry point before executing the app.
    """
    for ep in entry_points().get(ZENITH_SUBCOMMANDS_ENTRY_POINT, []):
        app.add_command(ep.load(), ep.name)
    app()
