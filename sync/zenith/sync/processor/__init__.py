import importlib.metadata

from .. import config  # noqa: TID252
from .base import Processor

EP_GROUP = "zenith.sync.processors"


def load(config_obj: config.SyncConfig) -> Processor:
    """
    Loads the processor from the given configuration.
    """
    (ep,) = importlib.metadata.entry_points(
        group=EP_GROUP, name=config_obj.processor_type
    )
    processor_type: type[Processor] = ep.load()
    return processor_type.from_config(config_obj)
