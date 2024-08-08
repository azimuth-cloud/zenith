import typing as t

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.serialization import load_ssh_public_key

from pydantic import BaseModel, StringConstraints, constr, model_validator, computed_field
from pydantic.functional_validators import AfterValidator

from .config import settings, SSHPublicKeyType


def is_reserved_subdomain(v):
    """
    Validates whether the given value is a reserved subdomain.
    """
    if v in settings.reserved_subdomains:
        raise ValueError(f"'{v}' is a reserved subdomain")
    else:
        return v


#: Annotated type for a Zenith subdomain
#: Subdomains must be at most 63 characters long, can only contain alphanumeric characters
#: and hyphens, and cannot start or end with a hyphen
#: In addition, this will eventually become a Kubernetes service name and Kubernetes service
#: names must start with a letter and be lowercase
#: See https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#rfc-1035-label-names
Subdomain = t.Annotated[
    str,
    StringConstraints(pattern = r"^[a-z][a-z0-9-]*?[a-z0-9]$", max_length = 63),
    AfterValidator(is_reserved_subdomain)
]


def validate_ssh_key(v):
    """
    Validates the given value as an SSH public key.
    """
    # Try to load the public key using cryptography
    try:
        public_key = load_ssh_public_key(v.encode())
    except (ValueError, UnsupportedAlgorithm):
        raise ValueError("Not a valid SSH public key.")
    # Now we know it is a valid SSH key, we can get the type as a string
    key_type = v.split()[0]
    # Test whether the key type is an allowed key type
    if key_type not in settings.ssh_allowed_key_types:
        raise ValueError(f"Keys of type '{key_type}' are not permitted.")
    # If the key is an RSA key, check the minimum size
    if key_type == SSHPublicKeyType.RSA and public_key.key_size < settings.ssh_rsa_min_bits:
        message = "RSA keys must have a minimum of {} bits ({} given).".format(
            settings.ssh_rsa_min_bits,
            public_key.key_size
        )
        raise ValueError(message)
    # The key is valid! Hooray!
    return v


#: Annotated type for an SSH public key
SSHPublicKey = t.Annotated[str, AfterValidator(validate_ssh_key)]


class ReservationRequest(BaseModel):
    """
    Model for a request to reserve a subdomain.
    """
    #: The subdomain to reserve
    subdomain: t.Optional[Subdomain] = None
    #: The public key to associate with the subdomain
    public_key: t.Optional[SSHPublicKey] = None

    @model_validator(mode = "before")
    @classmethod
    def validate_legacy_public_keys(cls, data: t.Any):
        """
        Allows clients to specify a list of SSH public keys for backwards compatibility.

        If the list contains exactly one item, it is used as the public key. In all
        other cases a validation error is raised.
        """
        if (
            isinstance(data, dict) and
            "public_key" not in data and
            "public_keys" in data and
            isinstance(data["public_keys"], list) and
            len(data["public_keys"]) == 1
        ):
            data["public_key"] = data["public_keys"][0]
        return data


class Reservation(BaseModel):
    """
    Model for a successful reservation.
    """
    #: The subdomain that was reserved
    subdomain: Subdomain
    #: The FQDN for the subdomain that was reserved
    fqdn: constr(min_length = 1)
    #: The token to use to associate public keys with the subdomain if no keys were given
    token: t.Optional[str] = None
    #: The fingerprint of the key that was registered, if given
    fingerprint: t.Optional[str] = None

    @computed_field
    @property
    def fingerprints(self) -> t.List[str]:
        """
        A list of fingerprints, for compatibility with older clients.
        """
        if self.fingerprint:
            return [self.fingerprint]
        else:
            return []


class VerificationRequest(BaseModel):
    """
    Model for a request to verify that a public key has an associated subdomain.
    """
    #: The public key to check
    public_key: SSHPublicKey


class VerificationResult(BaseModel):
    """
    Model for a verification result indicating the associated subdomain for a public key.
    """
    #: The associated subdomain
    subdomain: Subdomain
    #: The public key
    public_key: SSHPublicKey


class PublicKeyAssociationRequest(BaseModel):
    """
    Model for a request to associate public keys with a subdomain.
    """
    #: The token for the request
    token: constr(min_length = 1)
    #: The public key to associate with the subdomain
    public_key: SSHPublicKey

    @model_validator(mode = "before")
    @classmethod
    def validate_legacy_public_keys(cls, data: t.Any):
        """
        Allows clients to specify a list of SSH public keys for backwards compatibility.

        If the list contains exactly one item, it is used as the public key. In all
        other cases a validation error is raised.
        """
        if (
            isinstance(data, dict) and
            "public_key" not in data and
            "public_keys" in data and
            isinstance(data["public_keys"], list) and
            len(data["public_keys"]) == 1
        ):
            data["public_key"] = data["public_keys"][0]
        return data


class PublicKeyAssociation(BaseModel):
    """
    Model for a successful public key association.
    """
    #: The subdomain that the keys were associated with
    subdomain: str
    #: The fingerprint of the public key that was associated with the subdomain
    fingerprint: str

    @computed_field
    @property
    def fingerprints(self) -> t.List[str]:
        """
        A list of fingerprints, for compatibility with older clients.
        """
        return [self.fingerprint]


class Error(BaseModel):
    """
    Model for an error response.
    """
    #: The error message
    detail: str
