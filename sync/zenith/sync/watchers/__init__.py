import importlib.metadata
import typing as t

from .. import config

from .base import ServiceWatcher


EP_GROUP = "zenith.sync.watchers"


def load(config_obj: config.SyncConfig) -> ServiceWatcher:
    """
    Loads the watcher from the given configuration.
    """
    (ep, ) = importlib.metadata.entry_points(group = EP_GROUP, name = config_obj.watcher_type)
    watcher_type: t.Type[ServiceWatcher] = ep.load()
    return watcher_type.from_config(config_obj)
