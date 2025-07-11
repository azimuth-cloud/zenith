import importlib.metadata

from .. import config  # noqa: TID252
from .base import Store

EP_GROUP = "zenith.sync.stores"


def load(config_obj: config.SyncConfig) -> Store:
    """
    Loads the store from the given configuration.
    """
    (ep,) = importlib.metadata.entry_points(group=EP_GROUP, name=config_obj.store_type)
    store_type: type[Store] = ep.load()
    return store_type.from_config(config_obj)
