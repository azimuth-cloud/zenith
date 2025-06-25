import importlib.metadata

from .. import config  # noqa: TID252
from .base import (
    Backend,
    PublicKeyAlreadyAssociated,  # noqa: F401
    PublicKeyHasMultipleAssociations,  # noqa: F401
    PublicKeyNotAssociated,  # noqa: F401
    SubdomainAlreadyInitialised,  # noqa: F401
    SubdomainAlreadyReserved,  # noqa: F401
    SubdomainNotReserved,  # noqa: F401
)

EP_GROUP = "zenith.registrar.backends"


def load(config_obj: config.RegistrarConfig) -> Backend:
    """
    Loads the reconciler from the given configuration.
    """
    (ep,) = importlib.metadata.entry_points(
        group=EP_GROUP, name=config_obj.backend_type
    )
    backend_type: type[Backend] = ep.load()
    return backend_type.from_config(config_obj)
