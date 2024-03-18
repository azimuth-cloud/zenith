import enum
import logging
import typing

from .. import config


class TunnelStatus(enum.Enum):
    """
    Enumeration of possible statuses for a tunnel.
    """
    PASSING = "passing"
    WARNING = "warning"
    CRITICAL = "critical"


class Backend:
    """
    Base class for an SSHD backend.
    """
    def tunnel_check_host_and_port(self, host: str, port: int) -> bool:
        """
        Checks if there is already an existing service with the same host and port.

        Returns true if the host and port is safe to use, false otherwise.
        """
        raise NotImplementedError

    def tunnel_init(
        self,
        subdomain: str,
        host: str,
        port: int,
        ttl: int,
        config_dict: typing.Dict[str, typing.Any]
    ) -> str:
        """
        Initialise a tunnel with the given config and return the tunnel ID.
        """
        raise NotImplementedError

    def tunnel_heartbeat(self, id: str, status: TunnelStatus):
        """
        Send a heartbeat for the specified tunnel.
        """
        raise NotImplementedError

    def tunnel_terminate(self, id: str):
        """
        Terminate the specified tunnel.
        """
        raise NotImplementedError

    def startup(self):
        """
        Perform any startup tasks that are required.
        """

    def shutdown(self):
        """
        Perform any shutdown tasks that are required.
        """

    def __enter__(self):
        self.startup()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.shutdown()

    @classmethod
    def from_config(cls, logger: logging.Logger, config_obj: config.SSHDConfig) -> "Backend":
        """
        Initialises an instance of the backend from a config object.
        """
        raise NotImplementedError
