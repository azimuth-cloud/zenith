import importlib.metadata
import typing as t

from .. import config

from .base import (
    Backend,
    SubdomainAlreadyReserved,
    SubdomainAlreadyInitialised,
    PublicKeyNotAssociated
)


EP_GROUP = "zenith.registrar.backends"


def load(config_obj: config.RegistrarConfig) -> Backend:
    """
    Loads the reconciler from the given configuration.
    """
    (ep, ) = importlib.metadata.entry_points(group = EP_GROUP, name = config_obj.backend_type)
    backend_type: t.Type[Backend] = ep.load()
    return backend_type.from_config(config_obj)
