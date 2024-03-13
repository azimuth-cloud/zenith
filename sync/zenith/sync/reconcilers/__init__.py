import importlib.metadata
import typing as t

from .. import config

from .base import ServiceReconciler


EP_GROUP = "zenith.sync.reconcilers"


def load(config_obj: config.SyncConfig) -> ServiceReconciler:
    """
    Loads the reconciler from the given configuration.
    """
    (ep, ) = importlib.metadata.entry_points(group = EP_GROUP, name = config_obj.reconciler_type)
    reconciler_type: t.Type[ServiceReconciler] = ep.load()
    return reconciler_type.from_config(config_obj)
