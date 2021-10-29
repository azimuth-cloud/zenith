import dataclasses
import enum
import typing


@dataclasses.dataclass
class Endpoint:
    """
    Represents an endpoint for a service.
    """
    #: The address for the endpoint
    address: str
    #: The port for the endpoint
    port: int


@dataclasses.dataclass
class Service:
    """
    Represents a service with metadata and healthy endpoints.
    """
    #: The name of the service
    name: str
    #: The metadata for the service
    metadata: typing.Mapping[str, str] = dataclasses.field(default_factory = dict)
    #: The healthy endpoints for the service
    endpoints: typing.Iterable[Endpoint] = dataclasses.field(default_factory = list)
    #: The TLS configuration for the service
    #: Should be a dict with the keys "tls-cert", "tls-key" and "tls-client-ca"
    tls: typing.Mapping[str, str] = dataclasses.field(default_factory = dict)


@enum.unique
class EventKind(enum.Enum):
    """
    Represents the possible event types for services.
    """
    #: Represents a newly created service
    CREATED = "CREATED"
    #: Represents an updated service
    UPDATED = "UPDATED"
    #: Represents a deleted service
    DELETED = "DELETED"


@dataclasses.dataclass
class Event:
    """
    Class representing an event for a service.
    """
    #: The kind of the event
    kind: EventKind
    #: The new state of the service that the event affects
    service: typing.Optional[Service] = None
