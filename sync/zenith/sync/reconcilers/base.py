from .. import config, watchers


class ServiceReconciler:
    """
    Reconciles services from a watcher with the target system.
    """
    async def run(self, source: watchers.ServiceWatcher):
        """
        Run the reconciler against services from the given service watcher.
        """
        raise NotImplementedError

    @classmethod
    def from_config(cls, config_obj: config.SyncConfig) -> "ServiceReconciler":
        """
        Initialises an instance of the reconciler from a config object.
        """
        raise NotImplementedError
