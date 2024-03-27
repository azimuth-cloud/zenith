import importlib.metadata
import logging
import typing as t

from .. import config

from .base import Backend, TunnelStatus


EP_GROUP = "zenith.sshd.backends"


def load(logger: logging.Logger, config_obj: config.SSHDConfig) -> Backend:
    """
    Loads the reconciler from the given configuration.
    """
    (ep, ) = importlib.metadata.entry_points(group = EP_GROUP, name = config_obj.backend_type)
    backend_type: t.Type[Backend] = ep.load()
    return backend_type.from_config(logger, config_obj)
