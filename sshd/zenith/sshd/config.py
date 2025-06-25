import socket

from configomatic import Configuration, LoggingConfiguration
from pydantic import DirectoryPath, Field, FilePath, conint, constr


def default_service_host():
    """
    Returns the default service host.
    """
    # By default, use the IP address of the host running the script
    return socket.gethostbyname(socket.gethostname())


class SSHDConfig(
    Configuration,
    default_path="/etc/zenith/sshd.yaml",
    path_env_var="ZENITH_SSHD_CONFIG",
    env_prefix="ZENITH_SSHD",
):
    """
    Configuration model for the zenith-sshd package.
    """

    #: The logging configuration
    logging: LoggingConfiguration = Field(default_factory=LoggingConfiguration)

    #: The backend type to use
    backend_type: constr(min_length=1) = "crd"

    #: The API version of the resources when using the CRD backend
    crd_api_version: str = "zenith.stackhpc.com/v1alpha1"
    #: The target namespace for the CRD backend
    crd_target_namespace: str = "zenith-services"
    #: The maximum number of endpoints that are permitted on a single resource
    crd_max_endpoints: conint(gt=0) = 50

    #: The address of the Consul server
    consul_address: str = "127.0.0.1"
    #: The port of the Consul server
    consul_port: conint(gt=0) = 8500
    #: The prefix to use for Consul keys
    consul_key_prefix: str = "zenith/services"
    #: The tag to use when registering services with Consul
    consul_service_tag: str = "zenith-service"

    #: The heartbeat interval for tunnels
    #: This is only used if no liveness check is configured for a tunnel
    heartbeat_interval: conint(gt=0) = 10
    #: The number of times that posting a heartbeat can fail before a tunnel is closed
    heartbeat_failures: int = 3
    #: The number of seconds after the last heartbeat that a tunnel should be reaped
    reap_after: conint(gt=0) = 120

    #: The host to use when registering services with Consul
    service_host: str = Field(default_factory=default_service_host)
    #: The number of seconds to wait to receive a tunnel configuration before exiting
    configure_timeout: int = 5

    #: The URL of the Zenith registrar service
    registrar_url: str

    #: The SSHD executable location
    sshd_executable: FilePath = "/usr/sbin/sshd"
    #: The SSHD run directory
    run_directory: DirectoryPath = "/var/run/sshd"

    @property
    def consul_url(self):
        """
        The URL to use to access Consul.
        """
        return f"http://{self.consul_address}:{self.consul_port}"
