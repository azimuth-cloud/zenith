import socket

from pydantic import DirectoryPath, Field

from zenith.common.config import Configuration


def default_service_host():
    """
    Returns the default service host.
    """
    # By default, use the IP address of the host running the script
    return socket.gethostbyname(socket.gethostname())


class SSHDConfig(Configuration):
    """
    Configuration model for the zenith-sshd package.
    """
    class Config:
        default_path = '/etc/zenith/sshd.yaml'
        path_env_var = 'ZENITH_SSHD_CONFIG'
        env_prefix = 'ZENITH_SSHD'

    #: The address of the Consul server
    consul_address: str = "127.0.0.1"
    #: The port of the Consul server
    consul_port: int = 8500
    #: The TTL for the services created in Consul
    consul_service_ttl: str = "30s"
    #: The heartbeat interval for services created in Consul
    consul_heartbeat_interval: int = 10
    #: The interval after which a service in Consul will be deregistered
    consul_deregister_interval: str = "5m"
    #: The number of times that posting a heartbeat to Consul can fail before a tunnel is closed
    consul_heartbeat_failures: int = 3
    #: The host to use when registering services with Consul
    service_host: str = Field(default_factory = default_service_host)
    #: The tag to use when registering services with Consul
    service_tag: str = "zenith-service"
    #: The number of seconds to wait to receive a tunnel configuration before exiting
    configure_timeout: int = 5
    #: The SSHD run directory
    run_directory: DirectoryPath = "/var/run/sshd"

    @property
    def consul_url(self):
        """
        The URL to use to access Consul.
        """
        return f"http://{self.address}:{self.port}"
