import enum
import typing as t

from pydantic import TypeAdapter, Field, AnyHttpUrl as PyAnyHttpUrl, conint, constr
from pydantic.functional_validators import AfterValidator

from configomatic import Configuration as BaseConfiguration


#: Type for a string that validates as a URL
AnyHttpUrl = t.Annotated[
    str,
    AfterValidator(lambda v: str(TypeAdapter(PyAnyHttpUrl).validate_python(v)))
]


class ContainerImagePullPolicy(str, enum.Enum):
    """
    Enum of possible options for the container image pull policy.
    """
    IF_NOT_PRESENT = "IfNotPresent"
    ALWAYS = "Always"
    NEVER = "Never"


class Configuration(
    BaseConfiguration,
    default_path = "/etc/zenith/operator.yaml",
    path_env_var = "ZENITH_OPERATOR_CONFIG",
    env_prefix = "ZENITH_OPERATOR"
):
    """
    Top-level configuration model.
    """
    #: The API group of the cluster CRDs
    api_group: constr(min_length = 1) = "zenith.stackhpc.com"

    #: The amount of time (seconds) before a watch is forcefully restarted
    watch_timeout: conint(gt = 0) = 600

    #: The base domain used for cluster services
    cluster_service_domain: constr(pattern =r"^[a-z0-9.-]+$") = "svc.cluster.local"

    #: The default tag for Zenith images used by the operator
    default_image_tag: constr(pattern =r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$") = "main"
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

    #: The default debug status for clients if not specified
    default_debug: bool = False


settings = Configuration()
