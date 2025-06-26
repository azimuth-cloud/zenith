import importlib.metadata
import logging

from .. import config  # noqa: TID252
from .base import Backend, TunnelStatus  # noqa: F401

EP_GROUP = "zenith.sshd.backends"


def load(logger: logging.Logger, config_obj: config.SSHDConfig) -> Backend:
    """
    Loads the reconciler from the given configuration.
    """
    (ep,) = importlib.metadata.entry_points(
        group=EP_GROUP, name=config_obj.backend_type
    )
    backend_type: type[Backend] = ep.load()
    return backend_type.from_config(logger, config_obj)
