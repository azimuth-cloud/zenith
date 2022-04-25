import typing as t

from pydantic import Field, AnyHttpUrl, conint, constr

from configomatic import Configuration as BaseConfiguration, LoggingConfiguration


class Configuration(BaseConfiguration):
    """
    Top-level configuration model.
    """
    class Config:
        default_path = "/etc/zenith/operator.yaml"
        path_env_var = "ZENITH_OPERATOR_CONFIG"
        env_prefix = "ZENITH_OPERATOR"

    #: The logging configuration
    logging: LoggingConfiguration = Field(default_factory = LoggingConfiguration)

    #: The API group of the cluster CRDs
    api_group: constr(min_length = 1) = "zenith.stackhpc.com"

    #: The base domain used for cluster services
    cluster_service_domain: constr(regex = r"^[a-z0-9.-]+$") = "svc.cluster.local"

    #: The admin URL for the Zenith registrar
    registrar_admin_url: AnyHttpUrl
    #: The host for the Zenith SSHD service
    sshd_host: constr(min_length = 1)
    #: The port for the Zenith SSHD service
    sshd_port: conint(gt = 0) = 22


settings = Configuration()
