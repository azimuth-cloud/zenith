import socket

from pydantic import DirectoryPath, FilePath, Field, conint, validator
from pydantic.utils import deep_update

from configomatic import Configuration, LoggingConfiguration


def default_service_host():
    """
    Returns the default service host.
    """
    # By default, use the IP address of the host running the script
    return socket.gethostbyname(socket.gethostname())


class SSHDLoggingConfig(LoggingConfiguration):
    """
    Custom logging configuration for the zenith-sshd package.
    """
    @validator("formatters", pre = True, always = True)
    def default_formatters(cls, v):
        return deep_update(
            {
                # Default format used for regular log messages
                "default": {
                    "format": "[%(levelname)s] %(message)s",
                },
                # Format for logs that are sent to tunnel clients
                "tunnel_client": {
                    "format": "[%(levelname)s] [SERVER] %(message)s",
                },
            },
            v or {}
        )
    
    @validator("handlers", pre = True, always = True)
    def default_handlers(cls, v):
        return deep_update(
            {
                # Handlers for stdout/err with default formatting
                "stdout": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",
                    "formatter": "default",
                    "filters": ["less_than_warning"],
                },
                "stderr": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stderr",
                    "formatter": "default",
                    "level": "WARNING",
                },
                # Handlers for stdout/err for tunnel clients
                "tunnel_client_stdout": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",
                    "formatter": "tunnel_client",
                    "filters": ["less_than_warning"],
                },
                "tunnel_client_stderr": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stderr",
                    "formatter": "tunnel_client",
                    "level": "WARNING",
                },
            },
            v or {}
        )
    
    @validator("loggers", pre = True, always = True)
    def default_loggers(cls, v):
        return deep_update(
            {
                "": {
                    "handlers": ["stdout", "stderr"],
                    "level": "INFO",
                    "propagate": True
                },
                "zenith.sshd.tunnel": {
                    "handlers": [
                        "tunnel_client_stdout",
                        "tunnel_client_stderr",
                    ],
                    "level": "INFO",
                    "propagate": False
                },
            },
            v or {}
        )


class SSHDConfig(Configuration):
    """
    Configuration model for the zenith-sshd package.
    """
    class Config:
        default_path = "/etc/zenith/sshd.yaml"
        path_env_var = "ZENITH_SSHD_CONFIG"
        env_prefix = "ZENITH_SSHD"

    #: The logging configuration
    logging: SSHDLoggingConfig = Field(default_factory = SSHDLoggingConfig)

    #: The address of the Consul server
    consul_address: str = "127.0.0.1"
    #: The port of the Consul server
    consul_port: conint(gt = 0) = 8500
    #: The heartbeat interval for services created in Consul
    #: This is only used if no liveness check is configured for the tunnel
    consul_heartbeat_interval: conint(gt = 0) = 10
    #: The interval after which a service in Consul will be deregistered
    consul_deregister_interval: conint(gt = 0) = 600
    #: The number of times that posting a heartbeat to Consul can fail before a tunnel is closed
    consul_heartbeat_failures: int = 3
    #: The prefix to use for Consul keys
    consul_key_prefix: str = "zenith/services"
    #: The host to use when registering services with Consul
    service_host: str = Field(default_factory = default_service_host)
    #: The tag to use when registering services with Consul
    service_tag: str = "zenith-service"
    #: The number of seconds to wait to receive a tunnel configuration before exiting
    configure_timeout: int = 5
    #: The metadata key to use for the backend protocol
    backend_protocol_metadata_key: str = "backend-protocol"
    #: The metadata key to use for the read timeout
    read_timeout_metadata_key: str = "read-timeout"
    #: The metadata key to indicate that auth should be skipped
    skip_auth_metadata_key: str = "skip-auth"
    #: The prefix to use for metadata items containing authentication parameters
    auth_param_metadata_prefix: str = "auth-"

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
