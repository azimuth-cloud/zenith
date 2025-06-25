import importlib.metadata
import typing as t

from .. import config

from .base import Processor


EP_GROUP = "zenith.sync.processors"


def load(config_obj: config.SyncConfig) -> Processor:
    """
    Loads the processor from the given configuration.
    """
    (ep,) = importlib.metadata.entry_points(
        group=EP_GROUP, name=config_obj.processor_type
    )
    processor_type: t.Type[Processor] = ep.load()
    return processor_type.from_config(config_obj)
