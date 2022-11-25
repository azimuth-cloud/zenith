import typing as t

from pydantic import Extra, Field, constr, validator

from kube_custom_resource import CustomResource, schema

from ...config import settings


class ContainerImagePullPolicy(str, schema.Enum):
    """
    Enum of possible options for the container image pull policy.
    """
    IF_NOT_PRESENT = "IfNotPresent"
    ALWAYS = "Always"
    NEVER = "Never"


class ContainerImage(schema.BaseModel):
    """
    Model for a container image.
    """
    pull_policy: ContainerImagePullPolicy = Field(
        ContainerImagePullPolicy.IF_NOT_PRESENT,
        description = "The pull policy for the container image."
    )
    tag: constr(regex = r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$") = Field(
        settings.default_image_tag,
        description = "The tag for the container image."
    )


class ContainerResources(schema.BaseModel):
    """
    Model for the resources for a container.
    """
    requests: schema.Dict[str, str] = Field(
        default_factory = dict,
        description = "The resource requests for the container."
    )
    limits: schema.Dict[str, str] = Field(
        default_factory = dict,
        description = "The resource limits for the container."
    )


class UpstreamScheme(str, schema.Enum):
    """
    Enum of possible options for the upstream scheme.
    """
    HTTP = "http"
    HTTPS = "https"


class UpstreamSpec(schema.BaseModel):
    """
    Model for the upstream section of a client spec.
    """
    service_name: constr(regex = r"^[a-z0-9-]+$") = Field(
        ...,
        description = "The name of the service to use as the upstream."
    )
    port: t.Optional[schema.IntOrString] = Field(
        None,
        description = (
            "The service port to use for the upstream. "
            "Can be either a port name or a number. "
            "If not given, the first port of the service is used."
        )
    )
    scheme: UpstreamScheme = Field(
        UpstreamScheme.HTTP,
        description = "The scheme to use when forwarding traffic to the upstream."
    )
    readTimeout: t.Optional[int] = Field(
        None,
        description = "The read timeout for the upstream."
    )

    @validator("port")
    def validate_port(cls, v):
        """
        Validates the given port.
        """
        # If the port is an integer, it must be > 0
        try:
            v = int(v)
        except ValueError:
            return v
        else:
            if v > 0:
                return str(v)
            else:
                raise ValueError("must be greater than 0")


class ZenithClientAuthSpec(schema.BaseModel):
    """
    Model for the auth section of a Zenith client spec.
    """
    skip: bool = Field(
        False,
        description = (
            "Indicates whether to apply authentication for the service at "
            "the Zenith proxy."
        )
    )
    params: schema.Dict[str, str] = Field(
        default_factory = dict,
        description = (
            "Parameters for the Zenith authentication callout. "
            "The available parameters depend on the target Zenith server."
        )
    )


class ZenithClientContainerImage(ContainerImage):
    """
    Model for the image for the Zenith client container.
    """
    repository: constr(regex = r"^([a-z0-9.-]+(:\d+)?/)?[a-z0-9._/-]+$") = Field(
        "ghcr.io/stackhpc/zenith-client",
        description = "The repository for the container image."
    )


class MITMProxyAuthInjectType(str, schema.Enum):
    """
    Enum of possible options for the MITM proxy auth injection type.
    """
    NONE = "None"
    BASIC = "Basic"
    BEARER = "Bearer"
    SERVICE_ACCOUNT = "ServiceAccount"


class MITMProxyAuthInjectBasic(schema.BaseModel):
    """
    Model for basic auth injection parameters.
    """
    secret_name: constr(regex = r"^[a-z0-9-]+$") = Field(
        ...,
        description = "The name of the secret containing basic auth credentials."
    )
    username_key: constr(min_length = 1) = Field(
        "username",
        description = "The key of the username within the secret."
    )
    password_key: constr(min_length = 1) = Field(
        "password",
        description = "The key of the password within the secret."
    )


class MITMProxyAuthInjectBearer(schema.BaseModel):
    """
    Model for bearer auth injection parameters.
    """
    secret_name: constr(regex = r"^[a-z0-9-]+$") = Field(
        ...,
        description = "The name of the secret containing the bearer token."
    )
    token_key: constr(min_length = 1) = Field(
        "token",
        description = "The key of the bearer token within the secret."
    )
    header_name: constr(min_length = 1) = Field(
        "Authorization",
        description = "The name of the header to use for the token."
    )
    header_prefix: constr(min_length = 1) = Field(
        "Bearer",
        description = "The prefix to add to the header value."
    )


class MITMProxyAuthInjectServiceAccount(schema.BaseModel):
    """
    Model for service account auth injection parameters.
    """
    cluster_role_name: constr(min_length = 1) = Field(
        ...,
        description = "The name of the cluster role to bind the service account to."
    )


class MITMProxyAuthInjectSpec(schema.BaseModel):
    """
    Model for the MITM proxy auth injection configuration.
    """
    type: MITMProxyAuthInjectType = Field(
        MITMProxyAuthInjectType.NONE,
        description = "The type of auth to inject."
    )
    basic: t.Optional[MITMProxyAuthInjectBasic] = Field(
        None,
        description = "Configuration for auth type 'Basic'."
    )
    bearer: t.Optional[MITMProxyAuthInjectBearer] = Field(
        None,
        description = "Configuration for auth type 'Bearer'."
    )
    service_account: t.Optional[MITMProxyAuthInjectServiceAccount] = Field(
        None,
        description = "Configuration for auth type 'ServiceAccount'."
    )

    @validator("basic", always = True)
    def validate_basic(cls, v, values, **kwargs):
        """
        Validates that basic auth configuration is present when required.
        """
        if values["type"] == MITMProxyAuthInjectType.BASIC and v is None:
            raise ValueError("required when .spec.mitmProxy.authInject.type = Basic")
        return v

    @validator("bearer", always = True)
    def validate_bearer(cls, v, values, **kwargs):
        """
        Validates that bearer auth configuration is present when required.
        """
        if values["type"] == MITMProxyAuthInjectType.BEARER and v is None:
            raise ValueError("required when .spec.mitmProxy.authInject.type = Bearer")
        return v

    @validator("service_account", always = True)
    def validate_service_account(cls, v, values, **kwargs):
        """
        Validates that service account auth configuration is present when required.
        """
        if values["type"] == MITMProxyAuthInjectType.SERVICE_ACCOUNT and v is None:
            return MITMProxyAuthInjectServiceAccount()
        else:
            return v


class MITMProxyContainerImage(ContainerImage):
    """
    Model for the image for the MITM proxy container.
    """
    repository: constr(regex = r"^([a-z0-9.-]+(:\d+)?/)?[a-z0-9._/-]+$") = Field(
        "ghcr.io/stackhpc/zenith-proxy",
        description = "The repository for the container image."
    )


class MITMProxySpec(schema.BaseModel):
    """
    Model for the MITM proxy section of a client spec.
    """
    enabled: bool = Field(
        False,
        description = "Indicates whether the MITM proxy is enabled."
    )
    port: schema.conint(ge = 1) = Field(
        8080,
        description = "The port that the MITM proxy should listen on."
    )
    auth_inject: MITMProxyAuthInjectSpec = Field(
        default_factory = MITMProxyAuthInjectSpec,
        description = "The authentication injection configuration for the MITM proxy."
    )
    image: MITMProxyContainerImage = Field(
        default_factory = MITMProxyContainerImage,
        description = "The image specification for the MITM proxy container."
    )
    resources: ContainerResources = Field(
        default_factory = ContainerResources,
        description = "The resources for the MITM proxy container."
    )


class LocalObjectReference(schema.BaseModel):
    """
    Model for an object reference.
    """
    name: constr(min_length = 1) = Field(
        ...,
        description = "The name of the object being referred to."
    )


class PodSecurityContext(schema.BaseModel):
    """
    Model for a pod security context.
    """
    class Config:
        extra = Extra.allow

    run_as_non_root: bool = Field(
        True,
        description = "Indicates that containers must run as a non-root user."
    )
    run_as_user: schema.conint(ge = 0) = Field(
        1001,
        description = "The UID to run the entrypoint of container processes."
    )


class SecurityContextCapabilities(schema.BaseModel):
    """
    Model for the capabilities of a container security context.
    """
    add: t.List[constr(min_length = 1)] = Field(
        default_factory = list,
        description = "The capabilities to add to the container."
    )
    drop: t.List[constr(min_length = 1)] = Field(
        default_factory = lambda: ["ALL"],
        description = "The capabilities to drop from the container."
    )


class ContainerSecurityContext(schema.BaseModel):
    """
    Model for the container security context.
    """    
    class Config:
        extra = Extra.allow

    allow_privilege_escalation: bool = Field(
        False,
        description = "Indicates whether the container is able to escalate privileges."
    )
    read_only_root_filesystem: bool = Field(
        True,
        description = "Indicates whether the container should use a read-only root filesystem."
    )
    capabilities: SecurityContextCapabilities = Field(
        default_factory = SecurityContextCapabilities,
        description = "The Linux capabilities for the container."
    )


class ClientSpec(schema.BaseModel):
    """
    Model for the spec of a Zenith client.
    """
    reservation_name: constr(regex = r"^[a-z0-9-]+$") = Field(
        ...,
        description = "The name of the Zenith reservation to use for the client."
    )
    upstream: UpstreamSpec = Field(
        ...,
        description = "The upstream specification for the client."
    )
    mitm_proxy: MITMProxySpec = Field(
        default_factory = MITMProxySpec,
        description = "The MITM proxy specification for the client."
    )
    image_pull_secrets: t.List[LocalObjectReference] = Field(
        default_factory = list,
        description = "The image pull secrets for client pods."
    )
    image: ZenithClientContainerImage = Field(
        default_factory = ZenithClientContainerImage,
        description = "The image specification for the Zenith client container."
    )
    auth: ZenithClientAuthSpec = Field(
        default_factory = ZenithClientAuthSpec,
        description = "The auth configuration for the Zenith client."
    )
    resources: ContainerResources = Field(
        default_factory = ContainerResources,
        description = "The resources for the Zenith client container."
    )
    replica_count: schema.conint(ge = 1) = Field(
        1,
        description = "The number of replicas for the client deployment."
    )
    pod_security_context: PodSecurityContext = Field(
        default_factory = PodSecurityContext,
        description = "The pod-level security context for client pods."
    )
    security_context: ContainerSecurityContext = Field(
        default_factory = ContainerSecurityContext,
        description = "The container-level security context for containers in client pods."
    )
    node_selector: schema.Dict[str, str] = Field(
        default_factory = dict,
        description = "The node labels required for a client pod to be scheduled."
    )
    affinity: schema.Dict[str, schema.Any] = Field(
        default_factory = dict,
        description = "The affinity constraints for client pods."
    )
    tolerations: t.List[schema.Dict[str, schema.Any]] = Field(
        default_factory = list,
        description = "The tolerations for client pods."
    )


class ClientPhase(str, schema.Enum):
    """
    Enum of possible phases for a Zenith client.
    """
    PENDING = "Pending"
    RESERVATION_READY = "ReservationReady"
    AVAILABLE = "Available"
    UNAVAILABLE = "Unavailable"
    FAILED = "Failed"
    UNKNOWN = "Unknown"


class ClientStatus(schema.BaseModel):
    """
    Model for the status of a Zenith client.
    """
    class Config:
        extra = Extra.allow

    phase: ClientPhase = Field(
        ClientPhase.UNKNOWN,
        description = "The phase of the client."
    )


class Client(
    CustomResource,
    subresources = {"status": {}},
    printer_columns = [
        {
            "name": "Phase",
            "type": "string",
            "jsonPath": ".status.phase",
        },
        {
            "name": "Upstream Service",
            "type": "string",
            "jsonPath": ".spec.upstream.serviceName",
        },
        {
            "name": "MITM Enabled",
            "type": "boolean",
            "jsonPath": ".spec.mitmProxy.enabled",
        },
        {
            "name": "MITM Auth",
            "type": "string",
            "jsonPath": ".spec.mitmProxy.authInject.type",
        },
    ]
):
    """
    Model for a Zenith client.
    """
    spec: ClientSpec = Field(
        ...,
        description = "The spec for the Zenith client."
    )
    status: ClientStatus = Field(
        default_factory = ClientStatus,
        description = "The status of the Zenith client."
    )
