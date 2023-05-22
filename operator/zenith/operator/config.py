import enum
import typing as t

from pydantic import Field, AnyHttpUrl, conint, constr

from configomatic import Configuration as BaseConfiguration


class ContainerImagePullPolicy(str, enum.Enum):
    """
    Enum of possible options for the container image pull policy.
    """
    IF_NOT_PRESENT = "IfNotPresent"
    ALWAYS = "Always"
    NEVER = "Never"


class Configuration(BaseConfiguration):
    """
    Top-level configuration model.
    """
    class Config:
        default_path = "/etc/zenith/operator.yaml"
        path_env_var = "ZENITH_OPERATOR_CONFIG"
        env_prefix = "ZENITH_OPERATOR"

    #: The API group of the cluster CRDs
    api_group: constr(min_length = 1) = "zenith.stackhpc.com"
    #: A list of categories to place CRDs into
    crd_categories: t.List[constr(min_length = 1)] = Field(
        default_factory = lambda: ["zenith"]
    )

    #: The base domain used for cluster services
    cluster_service_domain: constr(regex = r"^[a-z0-9.-]+$") = "svc.cluster.local"

    #: The default tag for Zenith images used by the operator
    default_image_tag: constr(regex = r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$") = "main"
    #: The default pull policy for images used by the operator
    default_image_pull_policy: ContainerImagePullPolicy = ContainerImagePullPolicy.IF_NOT_PRESENT

    #: The admin URL for the Zenith registrar
    registrar_admin_url: AnyHttpUrl
    #: The host for the Zenith SSHD service
    sshd_host: constr(min_length = 1)
    #: The port for the Zenith SSHD service
    sshd_port: conint(gt = 0) = 22

    #: The default external auth parameters for created clients
    default_external_auth_params: t.Dict[str, str] = Field(default_factory = dict)


settings = Configuration()
